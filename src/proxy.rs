use crate::cfproxy::*;
use crate::config::*;
use crate::crypto::*;
use crate::faketls;
use crate::ws::*;
use crate::{ldebug, linfo, lwarn};
use byteorder::{ByteOrder, LittleEndian};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Fronting flag — proxy/pool.py::_WsPool.try_fronting_first (начинается true)
// ---------------------------------------------------------------------------

static TRY_FRONTING_FIRST: AtomicBool = AtomicBool::new(true);

pub fn ws_pool_fronting_first() -> bool {
    TRY_FRONTING_FIRST.load(Ordering::Relaxed)
}

pub fn set_ws_pool_fronting_first(v: bool) {
    TRY_FRONTING_FIRST.store(v, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Target resolution
// ---------------------------------------------------------------------------

pub fn resolve_configured_target(dc: i32, is_media: bool) -> Option<String> {
    let map = DC_OPT.read();
    if is_media {
        if let Some(t) = map.get(&(-dc)) {
            if !t.is_empty() {
                return Some(t.clone());
            }
        }
    }
    if let Some(t) = map.get(&dc) {
        if !t.is_empty() {
            return Some(t.clone());
        }
    }
    None
}

pub fn resolve_fallback_target(dc: i32, _is_media: bool, is_test: bool) -> String {
    if is_test {
        DC_TEST_IPS
            .get(&dc)
            .map(|s| s.to_string())
            .unwrap_or_default()
    } else {
        DC_DEFAULT_IPS
            .get(&dc)
            .map(|s| s.to_string())
            .unwrap_or_default()
    }
}

pub fn ws_domains(dc: i32, is_media: bool) -> Vec<String> {
    let mut effective_dc = dc;
    if let Some(o) = DC_OVERRIDES.get(&dc) {
        effective_dc = *o;
    }
    if is_media {
        vec![
            format!("kws{}-1.web.telegram.org", effective_dc),
            format!("kws{}.web.telegram.org", effective_dc),
        ]
    } else {
        vec![
            format!("kws{}.web.telegram.org", effective_dc),
            format!("kws{}-1.web.telegram.org", effective_dc),
        ]
    }
}

pub fn ws_path_for(is_test: bool) -> &'static str {
    if is_test {
        WS_PATH_TEST
    } else {
        WS_PATH
    }
}

pub fn media_tag(is_media: bool) -> &'static str {
    if is_media {
        " media"
    } else {
        ""
    }
}

pub fn is_media_int(b: bool) -> i32 {
    if b {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// WsPool — порт proxy/pool.py::_WsPool
// refilling-backoff (1s..3600s), rotation протухших, fronting-first.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DcSlot {
    pub dc: i32,
    pub is_media: i32,
}

pub struct PoolEntry {
    pub ws: RawWebSocket,
    pub created: f64, // monotonic, как time.monotonic() в оригинале
}

struct SlotState {
    queue: Mutex<VecDeque<PoolEntry>>,
    refilling: AtomicI32,
}

pub struct WsPool {
    slots: Mutex<HashMap<DcSlot, Arc<SlotState>>>,
    rotating: Mutex<HashSet<DcSlot>>,
    refill_failures: Mutex<HashMap<DcSlot, (u32, f64)>>,
    cancel_token: CancellationToken,
}

impl WsPool {
    pub fn new(cancel_token: CancellationToken) -> WsPool {
        WsPool {
            slots: Mutex::new(HashMap::new()),
            rotating: Mutex::new(HashSet::new()),
            refill_failures: Mutex::new(HashMap::new()),
            cancel_token,
        }
    }

    async fn get_slot(&self, slot: DcSlot) -> Arc<SlotState> {
        let mut map = self.slots.lock().await;
        map.entry(slot)
            .or_insert_with(|| {
                Arc::new(SlotState {
                    queue: Mutex::new(VecDeque::with_capacity(16)),
                    refilling: AtomicI32::new(0),
                })
            })
            .clone()
    }

    pub async fn get(
        self: &Arc<Self>,
        dc: i32,
        is_media: bool,
        target_ip: String,
        domains: Vec<String>,
    ) -> Option<RawWebSocket> {
        let slot = DcSlot {
            dc,
            is_media: is_media_int(is_media),
        };
        let state = self.get_slot(slot).await;
        let now = now_monotonic();

        let mut ws: Option<RawWebSocket> = None;
        {
            let mut q = state.queue.lock().await;
            while let Some(entry) = q.pop_front() {
                let age = now - entry.created;
                if age > WS_POOL_REUSE_MAX_AGE || entry.ws.is_closed() {
                    let e = entry;
                    tokio::spawn(async move {
                        e.ws.close().await;
                    });
                    continue;
                }
                STATS.pool_hits.fetch_add(1, Ordering::Relaxed);
                ldebug!(
                    "WS pool hit DC{}{} (age={:.1}s, left={})",
                    dc,
                    if is_media { "m" } else { "" },
                    age,
                    q.len()
                );
                ws = Some(entry.ws);
                break;
            }
            if ws.is_none() {
                STATS.pool_misses.fetch_add(1, Ordering::Relaxed);
            }
        }

        if ws.is_some() {
            self.report_success(dc, is_media).await;
        }
        self.schedule_refill(slot, target_ip, domains).await;
        ws
    }

    async fn schedule_refill(
        self: &Arc<Self>,
        slot: DcSlot,
        target_ip: String,
        domains: Vec<String>,
    ) {
        // Backoff как в оригинале: не раньше _refill_after.
        {
            let failures = self.refill_failures.lock().await;
            if let Some((_, after)) = failures.get(&slot) {
                if now_monotonic() < *after {
                    return;
                }
            }
        }
        let state = self.get_slot(slot).await;
        if state
            .refilling
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        // pool_size <= 0 — преконнект отключён (как pool_size=0 в оригинале).
        if POOL_SIZE.load(Ordering::Relaxed) <= 0 {
            state.refilling.store(0, Ordering::SeqCst);
            return;
        }
        let pool = self.clone();
        spawn_refill_task(pool, slot, state, target_ip, domains);
    }

    async fn refill(
        self: Arc<Self>,
        slot: DcSlot,
        state: Arc<SlotState>,
        target_ip: String,
        domains: Vec<String>,
    ) {
        let _guard = RefillGuard {
            state: state.clone(),
        };
        let cur_len = state.queue.lock().await.len();
        let pool_sz = POOL_SIZE.load(Ordering::Relaxed).max(0) as usize;
        if cur_len >= pool_sz || pool_sz == 0 {
            return;
        }
        let needed = pool_sz - cur_len;

        let mut handles = Vec::new();
        for _ in 0..needed {
            let target_ip = target_ip.clone();
            let domains = domains.clone();
            let cancel = self.cancel_token.clone();
            handles.push(tokio::spawn(async move {
                tokio::select! {
                    _ = cancel.cancelled() => None,
                    r = connect_one_ws(&target_ip, &domains) => r,
                }
            }));
        }

        let mut connected = 0;
        for h in handles {
            if let Ok(Some(ws)) = h.await {
                let now = now_monotonic();
                let mut q = state.queue.lock().await;
                if q.len() < 16 {
                    q.push_back(PoolEntry { ws, created: now });
                    connected += 1;
                } else {
                    drop(q);
                    tokio::spawn(async move {
                        ws.close().await;
                    });
                }
            }
        }

        if connected > 0 {
            self.report_success(slot.dc, slot.is_media != 0).await;
            self.schedule_rotation(slot, target_ip, domains).await;
        } else {
            // Экспоненциальный backoff 1s..3600s как в оригинале.
            let mut failures = self.refill_failures.lock().await;
            let count = failures.get(&slot).map(|(c, _)| *c).unwrap_or(0) + 1;
            let shift = (count - 1).min(12);
            let delay = (WS_POOL_REFILL_BACKOFF_INITIAL * (2u64.pow(shift) as f64))
                .min(WS_POOL_REFILL_BACKOFF_MAX);
            failures.insert(slot, (count, now_monotonic() + delay));
            drop(failures);
            linfo!(
                "WS pool refill failed for DC{}{}, retry in {:.0}s",
                slot.dc,
                if slot.is_media != 0 { "m" } else { "" },
                delay
            );
        }
        ldebug!(
            "WS pool refilled DC{}{}: {} ready",
            slot.dc,
            if slot.is_media != 0 { "m" } else { "" },
            state.queue.lock().await.len()
        );
    }

    pub async fn report_success(&self, dc: i32, is_media: bool) {
        let slot = DcSlot {
            dc,
            is_media: is_media_int(is_media),
        };
        self.refill_failures.lock().await.remove(&slot);
    }

    async fn schedule_rotation(
        self: &Arc<Self>,
        slot: DcSlot,
        target_ip: String,
        domains: Vec<String>,
    ) {
        {
            let mut rotating = self.rotating.lock().await;
            if rotating.contains(&slot) {
                return;
            }
            rotating.insert(slot);
        }
        let pool = self.clone();
        let cancel = self.cancel_token.clone();
        spawn_rotate_task(pool, slot, target_ip, domains, cancel);
    }

    async fn rotate(
        self: Arc<Self>,
        slot: DcSlot,
        target_ip: String,
        domains: Vec<String>,
        cancel: CancellationToken,
    ) {
        loop {
            // Спим до ближайшего протухания, но не реже CHECK_INTERVAL.
            let sleep_dur = {
                let map = self.slots.lock().await;
                match map.get(&slot) {
                    Some(state) => {
                        let q = state.queue.lock().await;
                        if q.is_empty() {
                            None
                        } else {
                            let now = now_monotonic();
                            let min_expires = q
                                .iter()
                                .map(|e| e.created + WS_POOL_REUSE_MAX_AGE)
                                .fold(f64::INFINITY, f64::min);
                            Some((min_expires - now).clamp(0.0, WS_POOL_CHECK_INTERVAL))
                        }
                    }
                    None => None,
                }
            };
            let sleep_dur = match sleep_dur {
                Some(d) => d,
                None => break,
            };
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs_f64(sleep_dur)) => {}
            }

            let now = now_monotonic();
            let expired_count: usize;
            let ready_count: usize;
            {
                let map = self.slots.lock().await;
                let state = match map.get(&slot) {
                    Some(s) => s.clone(),
                    None => break,
                };
                let mut q = state.queue.lock().await;
                let mut ready = VecDeque::with_capacity(q.len());
                let mut expired = Vec::new();
                while let Some(e) = q.pop_front() {
                    if now - e.created >= WS_POOL_REUSE_MAX_AGE || e.ws.is_closed() {
                        expired.push(e.ws);
                    } else {
                        ready.push_back(e);
                    }
                }
                expired_count = expired.len();
                *q = ready;
                ready_count = q.len();
                for ws in expired {
                    tokio::spawn(async move {
                        ws.close().await;
                    });
                }
            }
            if expired_count > 0 {
                ldebug!(
                    "WS pool rotated DC{}{}: {} stale, {} ready",
                    slot.dc,
                    if slot.is_media != 0 { "m" } else { "" },
                    expired_count,
                    ready_count
                );
            }
            let pool_sz = POOL_SIZE.load(Ordering::Relaxed).max(0) as usize;
            if ready_count == 0 {
                break;
            }
            if ready_count < pool_sz {
                self.schedule_refill(slot, target_ip.clone(), domains.clone())
                    .await;
            }
        }
        self.rotating.lock().await.remove(&slot);
    }

    pub async fn warmup(self: &Arc<Self>, dc_opt_map: &HashMap<i32, String>) {
        let mut ndcs = 0;
        for (dc, target_ip) in dc_opt_map {
            if target_ip.is_empty() {
                continue;
            }
            ndcs += 1;
            for is_media in [false, true] {
                let domains = ws_domains(*dc, is_media);
                let slot = DcSlot {
                    dc: *dc,
                    is_media: is_media_int(is_media),
                };
                self.schedule_refill(slot, target_ip.clone(), domains).await;
            }
        }
        linfo!("WS pool warmup started for {} DC(s)", ndcs);
    }

    pub async fn idle_count(&self) -> usize {
        let map = self.slots.lock().await;
        let mut count = 0;
        for s in map.values() {
            count += s.queue.lock().await.len();
        }
        count
    }

    pub async fn close_all(&self) {
        let map = self.slots.lock().await;
        for s in map.values() {
            let mut q = s.queue.lock().await;
            for e in q.drain(..) {
                tokio::spawn(async move {
                    e.ws.close().await;
                });
            }
        }
    }

    pub async fn reset(&self) {
        self.close_all().await;
        self.slots.lock().await.clear();
        self.rotating.lock().await.clear();
        self.refill_failures.lock().await.clear();
        set_ws_pool_fronting_first(true);
    }
}

// RefillGuard снимает флаг refilling при выходе (аналог finally: discard).
struct RefillGuard {
    state: Arc<SlotState>,
}
impl Drop for RefillGuard {
    fn drop(&mut self) {
        self.state.refilling.store(0, Ordering::SeqCst);
    }
}

// Синхронные спавн-хелперы: разрывают цикл типов async-future
// (schedule_refill → refill → schedule_rotation → rotate → schedule_refill),
// о который спотыкается rustc (E0391). Sync-fn не вкладывает future одной
// async-функции в другую — внутри только JoinHandle.
fn spawn_refill_task(
    pool: Arc<WsPool>,
    slot: DcSlot,
    state: Arc<SlotState>,
    target_ip: String,
    domains: Vec<String>,
) {
    tokio::spawn(async move {
        pool.refill(slot, state, target_ip, domains).await;
    });
}

fn spawn_rotate_task(
    pool: Arc<WsPool>,
    slot: DcSlot,
    target_ip: String,
    domains: Vec<String>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        pool.rotate(slot, target_ip, domains, cancel).await;
    });
}

// ---------------------------------------------------------------------------
// CfWorkerPool — порт proxy/pool.py::_CfWorkerPool
// ---------------------------------------------------------------------------

pub struct CfWorkerEntry {
    pub ws: RawWebSocket,
    pub created: f64,
    pub worker_domain: String,
}

pub struct CfWorkerPool {
    idle: Mutex<HashMap<i32, VecDeque<CfWorkerEntry>>>,
    refilling: Mutex<HashSet<i32>>,
    exhausted_until: Mutex<HashMap<String, f64>>,
    cancel_token: CancellationToken,
}

impl CfWorkerPool {
    pub fn new(cancel_token: CancellationToken) -> CfWorkerPool {
        CfWorkerPool {
            idle: Mutex::new(HashMap::new()),
            refilling: Mutex::new(HashSet::new()),
            exhausted_until: Mutex::new(HashMap::new()),
            cancel_token,
        }
    }

    pub async fn get(
        self: &Arc<Self>,
        dc: i32,
        fallback_dst: String,
        worker_domains: Vec<String>,
    ) -> Option<(RawWebSocket, String)> {
        let now = now_monotonic();
        let entry = {
            let mut map = self.idle.lock().await;
            let bucket = map.entry(dc).or_insert_with(VecDeque::new);
            let mut hit = None;
            while let Some(e) = bucket.pop_front() {
                if now - e.created > CF_WORKER_POOL_MAX_AGE || e.ws.is_closed() {
                    let ws = e.ws;
                    tokio::spawn(async move {
                        ws.close().await;
                    });
                    continue;
                }
                hit = Some(e);
                break;
            }
            hit
        };
        match entry {
            Some(e) => {
                STATS.cf_pool_hits.fetch_add(1, Ordering::Relaxed);
                ldebug!(
                    "CF worker pool hit DC{} via {} (age={:.1}s)",
                    dc,
                    e.worker_domain,
                    now - e.created
                );
                self.schedule_refill(dc, fallback_dst, worker_domains).await;
                Some((e.ws, e.worker_domain))
            }
            None => {
                STATS.cf_pool_misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    async fn schedule_refill(&self, dc: i32, fallback_dst: String, worker_domains: Vec<String>) {
        {
            let mut r = self.refilling.lock().await;
            if r.contains(&dc) {
                return;
            }
            r.insert(dc);
        }
        // PER_DC_LIMIT уважаем через проверку размера в refill.
        let _ = (fallback_dst, worker_domains);
    }

    pub async fn refill_now(
        self: &Arc<Self>,
        dc: i32,
        fallback_dst: String,
        worker_domains: Vec<String>,
    ) {
        let should = {
            let mut r = self.refilling.lock().await;
            if r.contains(&dc) {
                false
            } else {
                r.insert(dc);
                true
            }
        };
        if !should {
            return;
        }
        let pool = self.clone();
        let cancel = self.cancel_token.clone();
        tokio::spawn(async move {
            let _cancel = cancel;
            {
                let map = pool.idle.lock().await;
                let cur = map.get(&dc).map(|b| b.len()).unwrap_or(0);
                if cur >= CF_WORKER_PER_DC_LIMIT.min(POOL_SIZE.load(Ordering::Relaxed).max(0) as usize) {
                    pool.refilling.lock().await.remove(&dc);
                    return;
                }
            }
            if let Some((ws, domain)) = pool
                .connect_one(worker_domains.clone(), fallback_dst.clone(), dc)
                .await
            {
                let mut map = pool.idle.lock().await;
                map.entry(dc)
                    .or_insert_with(VecDeque::new)
                    .push_back(CfWorkerEntry {
                        ws,
                        created: now_monotonic(),
                        worker_domain: domain,
                    });
                ldebug!("CF worker pool refilled DC{}: ready", dc);
            }
            pool.refilling.lock().await.remove(&dc);
        });
    }

    async fn connect_one(
        &self,
        worker_domains: Vec<String>,
        fallback_dst: String,
        dc: i32,
    ) -> Option<(RawWebSocket, String)> {
        // Worker всегда по WSS: Cloudflare на порту 80 отдаёт редирект на HTTPS.
        let secure = true;
        let query = format!("dst={}&dc={}", fallback_dst, dc);
        let path = format!("/apiws?{}", query);
        for worker_domain in self.available_domains(worker_domains).await {
            match ws_connect_full_opts(&worker_domain, &worker_domain, &path, 8.0, None, Some(secure))
                .await
            {
                Ok(ws) => return Some((ws, worker_domain)),
                Err(exc) => {
                    self.report_failure(&worker_domain, &exc).await;
                }
            }
        }
        None
    }

    pub async fn available_domains(&self, worker_domains: Vec<String>) -> Vec<String> {
        let now = now_unix_f64();
        let mut exhausted = self.exhausted_until.lock().await;
        let mut domains = Vec::new();
        let mut seen = HashSet::new();
        for domain in worker_domains {
            if !seen.insert(domain.clone()) {
                continue;
            }
            if let Some(until) = exhausted.get(&domain) {
                if *until > now {
                    continue;
                }
            }
            exhausted.remove(&domain);
            domains.push(domain);
        }
        drop(exhausted);
        // random.shuffle как в оригинале.
        {
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            domains.shuffle(&mut rng);
        }
        domains
    }

    pub async fn report_failure(&self, _worker_domain: &str, _exc: &WsError) {
        // TODO: picks up 429/daily-limit handling — как в оригинале пока no-op.
        return;
    }

    pub async fn warmup(self: &Arc<Self>, dc_opt_map: &HashMap<i32, String>) {
        let worker_domains = CF_WORKER_DOMAINS.read().clone();
        if worker_domains.is_empty() {
            return;
        }
        // CF worker греем только для DC, которых НЕТ в прямых редиректах.
        let fallbacks: Vec<(i32, String)> = DC_DEFAULT_IPS
            .iter()
            .filter(|(dc, _)| !dc_opt_map.contains_key(dc))
            .map(|(dc, ip)| (*dc, ip.to_string()))
            .collect();
        if fallbacks.is_empty() {
            return;
        }
        for (dc, fallback_dst) in &fallbacks {
            self.refill_now(*dc, fallback_dst.clone(), worker_domains.clone())
                .await;
        }
        linfo!("CF worker pool warmup started for {} DC(s)", fallbacks.len());
    }

    pub async fn close_all(&self) {
        let mut map = self.idle.lock().await;
        for bucket in map.values_mut() {
            for e in bucket.drain(..) {
                tokio::spawn(async move {
                    e.ws.close().await;
                });
            }
        }
    }

    pub async fn reset(&self) {
        self.close_all().await;
        self.idle.lock().await.clear();
        self.refilling.lock().await.clear();
        self.exhausted_until.lock().await.clear();
    }
}

// ---------------------------------------------------------------------------
// Shared pools (WS + CF worker) — один Arc на соединение.
// ---------------------------------------------------------------------------

pub struct ProxyPools {
    pub ws: Arc<WsPool>,
    pub cf_worker: Arc<CfWorkerPool>,
}

impl ProxyPools {
    pub fn new(cancel_token: CancellationToken) -> Self {
        ProxyPools {
            ws: Arc::new(WsPool::new(cancel_token.clone())),
            cf_worker: Arc::new(CfWorkerPool::new(cancel_token)),
        }
    }

    pub async fn warmup(&self, dc_opt_map: &HashMap<i32, String>) {
        self.ws.warmup(dc_opt_map).await;
        self.cf_worker.warmup(dc_opt_map).await;
    }

    pub async fn close_all(&self) {
        self.ws.close_all().await;
        self.cf_worker.close_all().await;
    }

    pub async fn reset(&self) {
        self.ws.reset().await;
        self.cf_worker.reset().await;
    }
}

// ---------------------------------------------------------------------------
// HTTP transport detection
// ---------------------------------------------------------------------------

pub fn is_http_transport(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    &data[..4] == b"POST"
        || &data[..3] == b"GET"
        || &data[..4] == b"HEAD"
        || (data.len() >= 7 && &data[..7] == b"OPTIONS")
}

// ---------------------------------------------------------------------------
// Bridge WS — generic core + TcpStream wrapper.
// Сессионная статистика как в bridge_ws_reencrypt оригинала.
// ---------------------------------------------------------------------------

/// Итог WS-сессии: нужен, чтобы пометить маршрут плохим, если через него
/// не пошёл трафик (Telegram «подключился», но висит на «Обновление...»).
#[derive(Debug, Clone, Copy, Default)]
pub struct BridgeOutcome {
    pub up_bytes: i64,
    pub down_bytes: i64,
    /// Клиент отправил данные, но ответа от Telegram не было дольше
    /// BRIDGE_FIRST_DOWNSTREAM_TIMEOUT — маршрут полуживой.
    pub stalled: bool,
}

pub async fn bridge_ws<R, W>(
    conn_read: R,
    conn_write: W,
    ws: RawWebSocket,
    label: String,
    dc: i32,
    is_media: bool,
    mut splitter: Option<MsgSplitter>,
    mut clt_dec: TrackedStream,
    mut clt_enc: TrackedStream,
    mut tg_enc: TrackedStream,
    mut tg_dec: TrackedStream,
    cancel_token: CancellationToken,
) -> BridgeOutcome
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let dc_tag = format!("DC{}{}", dc, if is_media { "m" } else { "" });
    let ws = Arc::new(ws);
    let last_activity = Arc::new(Mutex::new(std::time::Instant::now()));
    let cancel = Arc::new(tokio::sync::Notify::new());
    let start = now_monotonic();
    // Метка «клиент что-то отправил» и «пришёл первый ответ».
    let client_sent_at: Arc<Mutex<Option<std::time::Instant>>> = Arc::new(Mutex::new(None));
    let got_downstream = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stalled = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let mut conn_read = conn_read;
    let mut conn_write = conn_write;

    // ping keepalive (мобильное улучшение поверх оригинала).
    let ws_ping = ws.clone();
    let la_ping = last_activity.clone();
    let cancel_ping = cancel.clone();
    let cancel_token_ping = cancel_token.clone();
    let ping_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(BRIDGE_PING_INTERVAL);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = cancel_token_ping.cancelled() => return,
                _ = cancel_ping.notified() => return,
                _ = interval.tick() => {
                    let idle = la_ping.lock().await.elapsed();
                    if idle > BRIDGE_PING_INTERVAL {
                        if ws_ping.send_ping().await.is_err() {
                            cancel_ping.notify_waiters();
                            return;
                        }
                    }
                }
            }
        }
    });

    // watchdog: клиент отправил данные, а ответа нет — маршрут мёртвый.
    // Без этого Telegram остаётся в состоянии «Обновление...» навсегда,
    // потому что WS-соединение формально живое (101 + ping/pong).
    let watchdog_ws = ws.clone();
    let watchdog_sent = client_sent_at.clone();
    let watchdog_got = got_downstream.clone();
    let watchdog_stalled = stalled.clone();
    let watchdog_cancel = cancel.clone();
    let watchdog_token = cancel_token.clone();
    let watchdog_task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(BRIDGE_WATCHDOG_INTERVAL);
        loop {
            tokio::select! {
                _ = watchdog_token.cancelled() => return,
                _ = watchdog_cancel.notified() => return,
                _ = ticker.tick() => {
                    if watchdog_got.load(Ordering::Relaxed) {
                        return;
                    }
                    let sent = *watchdog_sent.lock().await;
                    if let Some(t) = sent {
                        if t.elapsed() >= BRIDGE_FIRST_DOWNSTREAM_TIMEOUT {
                            watchdog_stalled.store(true, Ordering::Relaxed);
                            lwarn!(
                                " WS session: нет ответа от Telegram {:.0}с после данных клиента — закрываю мёртвый маршрут",
                                t.elapsed().as_secs_f64()
                            );
                            watchdog_ws.close().await;
                            watchdog_cancel.notify_waiters();
                            return;
                        }
                    }
                }
            }
        }
    });

    // up: client -> ws
    let ws_up = ws.clone();
    let la_up = last_activity.clone();
    let cancel_up = cancel.clone();
    let cancel_token_up = cancel_token.clone();
    let up_bytes = Arc::new(std::sync::atomic::AtomicI64::new(0));
    let up_packets = Arc::new(std::sync::atomic::AtomicI64::new(0));
    let up_bytes_c = up_bytes.clone();
    let up_packets_c = up_packets.clone();
    let close_reason_up = Arc::new(Mutex::new(String::new()));
    let close_reason_up_c = close_reason_up.clone();
    let sent_at_up = client_sent_at.clone();
    let up_task = tokio::spawn(async move {
        let mut buf = vec![0u8; WS_BRIDGE_CHUNK_SIZE];
        loop {
            let read_res = tokio::select! {
                _ = cancel_token_up.cancelled() => break,
                _ = cancel_up.notified() => break,
                r = tokio::time::timeout(BRIDGE_READ_TIMEOUT, conn_read.read(&mut buf)) => r,
            };
            let n = match read_res {
                Ok(Ok(0)) => {
                    // EOF: flush splitter tail
                    if let Some(sp) = splitter.as_mut() {
                        let tail = sp.flush();
                        if !tail.is_empty() {
                            let r = if tail.len() > 1 {
                                ws_up.send_batch(&tail).await
                            } else {
                                ws_up.send(&tail[0]).await
                            };
                            if r.is_err() {
                                *close_reason_up_c.lock().await =
                                    "upstream: send_failed".to_string();
                                break;
                            }
                        }
                    }
                    break;
                }
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    *close_reason_up_c.lock().await =
                        format!("client: {}", e.kind());
                    break;
                }
                Err(_) => {
                    // Таймаут чтения от клиента сам по себе не повод рвать
                    // сессию: важна общая активность в обе стороны.
                    // Иначе здоровые простаивающие сессии Telegram
                    // переподключаются каждые 2 минуты.
                    if la_up.lock().await.elapsed() < BRIDGE_READ_TIMEOUT {
                        continue;
                    }
                    *close_reason_up_c.lock().await = "client: timeout".to_string();
                    break;
                }
            };

            let chunk = &mut buf[..n];
            STATS.bytes_up.fetch_add(n as i64, Ordering::Relaxed);
            up_bytes_c.fetch_add(n as i64, Ordering::Relaxed);
            up_packets_c.fetch_add(1, Ordering::Relaxed);
            *la_up.lock().await = std::time::Instant::now();

            clt_dec.xor(chunk);
            tg_enc.xor(chunk);

            let send_err = {
                if let Some(sp) = splitter.as_mut() {
                    let parts = sp.split(chunk);
                    if parts.len() > 1 {
                        ws_up.send_batch(&parts).await.is_err()
                    } else if parts.len() == 1 {
                        ws_up.send(&parts[0]).await.is_err()
                    } else {
                        false
                    }
                } else {
                    ws_up.send(chunk).await.is_err()
                }
            };
            if send_err {
                *close_reason_up_c.lock().await = "upstream: send_failed".to_string();
                break;
            }
            // Запоминаем момент первой отправки — watchdog ждёт ответ.
            let mut sent = sent_at_up.lock().await;
            if sent.is_none() {
                *sent = Some(std::time::Instant::now());
            }
        }
        cancel_up.notify_waiters();
    });

    // down: ws -> client
    let ws_down = ws.clone();
    let la_down = last_activity.clone();
    let cancel_down = cancel.clone();
    let cancel_token_down = cancel_token.clone();
    let down_bytes = Arc::new(std::sync::atomic::AtomicI64::new(0));
    let down_packets = Arc::new(std::sync::atomic::AtomicI64::new(0));
    let down_bytes_c = down_bytes.clone();
    let down_packets_c = down_packets.clone();
    let close_reason_down = Arc::new(Mutex::new(String::new()));
    let close_reason_down_c = close_reason_down.clone();
    let got_down_c = got_downstream.clone();
    let stalled_down_c = stalled.clone();
    let down_task = tokio::spawn(async move {
        loop {
            let recv_res = tokio::select! {
                _ = cancel_token_down.cancelled() => break,
                _ = cancel_down.notified() => break,
                r = ws_down.recv_with_timeout(BRIDGE_READ_TIMEOUT) => r,
            };
            let mut data = match recv_res {
                Ok(d) => d,
                Err(WsError::Timeout) => {
                    // Закрытие по watchdog уже выставило stalled: причину
                    // не перетираем, это и есть диагностика мёртвого маршрута.
                    if !stalled_down_c.load(Ordering::Relaxed) {
                        *close_reason_down_c.lock().await =
                            "upstream: timeout".to_string();
                    }
                    break;
                }
                Err(_) => {
                    let cur = close_reason_down_c.lock().await.clone();
                    if cur.is_empty() {
                        *close_reason_down_c.lock().await =
                            "upstream: ws_close".to_string();
                    }
                    break;
                }
            };
            let n = data.len();
            if n > 0 {
                got_down_c.store(true, Ordering::Relaxed);
            }
            STATS.bytes_down.fetch_add(n as i64, Ordering::Relaxed);
            down_bytes_c.fetch_add(n as i64, Ordering::Relaxed);
            down_packets_c.fetch_add(1, Ordering::Relaxed);
            *la_down.lock().await = std::time::Instant::now();

            tg_dec.xor(&mut data);
            clt_enc.xor(&mut data);
            if conn_write.write_all(&data).await.is_err() {
                *close_reason_down_c.lock().await = "client: write_failed".to_string();
                break;
            }
        }
        cancel_down.notify_waiters();
    });

    let _ = up_task.await;
    let _ = down_task.await;
    cancel.notify_waiters();
    ping_task.abort();
    watchdog_task.abort();

    let was_stalled = stalled.load(Ordering::Relaxed);
    let close_reason = {
        let up_r = close_reason_up.lock().await.clone();
        let down_r = close_reason_down.lock().await.clone();
        if was_stalled {
            "upstream: no_downstream".to_string()
        } else if !down_r.is_empty() {
            down_r
        } else if !up_r.is_empty() {
            up_r
        } else {
            "normal".to_string()
        }
    };
    let elapsed = now_monotonic() - start;
    linfo!(
        "[{}] {} WS session closed ({}): ^{}{} ({} pkts) v{}{} ({} pkts) in {:.1}s",
        label,
        dc_tag,
        close_reason,
        human_bytes(up_bytes.load(Ordering::Relaxed)),
        "",
        up_packets.load(Ordering::Relaxed),
        human_bytes(down_bytes.load(Ordering::Relaxed)),
        "",
        down_packets.load(Ordering::Relaxed),
        elapsed
    );

    ws.close().await;
    BridgeOutcome {
        up_bytes: up_bytes.load(Ordering::Relaxed),
        down_bytes: down_bytes.load(Ordering::Relaxed),
        stalled: was_stalled,
    }
}

/// Совместимость: bridge по TcpStream (разрезаем внутри).
pub async fn bridge_ws_stream(
    conn: TcpStream,
    ws: RawWebSocket,
    label: String,
    dc: i32,
    is_media: bool,
    splitter: Option<MsgSplitter>,
    clt_dec: TrackedStream,
    clt_enc: TrackedStream,
    tg_enc: TrackedStream,
    tg_dec: TrackedStream,
    cancel_token: CancellationToken,
) {
    let (conn_read, conn_write) = tokio::io::split(conn);
    bridge_ws(
        conn_read,
        conn_write,
        ws,
        label,
        dc,
        is_media,
        splitter,
        clt_dec,
        clt_enc,
        tg_enc,
        tg_dec,
        cancel_token,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Bridge TCP — generic core + wrapper.
// ---------------------------------------------------------------------------

pub async fn bridge_tcp<CR, CW>(
    mut c_read: CR,
    mut c_write: CW,
    mut remote: TcpStream,
    clt_dec: TrackedStream,
    clt_enc: TrackedStream,
    tg_enc: TrackedStream,
    tg_dec: TrackedStream,
    cancel_token: CancellationToken,
) -> bool
where
    CR: AsyncReadExt + Unpin + Send + 'static,
    CW: AsyncWriteExt + Unpin + Send + 'static,
{
    let (mut r_read, mut r_write) = remote.split();
    // Те же метрики, что и в WS-мосте: нужен детект «соединились, а данных нет».
    let client_sent = Arc::new(AtomicBool::new(false));
    let got_downstream = Arc::new(AtomicBool::new(false));
    let stalled = Arc::new(AtomicBool::new(false));

    let clt_dec = Arc::new(Mutex::new(clt_dec));
    let clt_enc = Arc::new(Mutex::new(clt_enc));
    let tg_enc = Arc::new(Mutex::new(tg_enc));
    let tg_dec = Arc::new(Mutex::new(tg_dec));

    let cancel = Arc::new(tokio::sync::Notify::new());

    let cancel_up = cancel.clone();
    let cancel_token_up = cancel_token.clone();
    let clt_dec_up = clt_dec.clone();
    let tg_enc_up = tg_enc.clone();
    let client_sent_up = client_sent.clone();
    let up = async move {
        let mut buf = vec![0u8; 131072];
        loop {
            let n = tokio::select! {
                _ = cancel_token_up.cancelled() => break,
                _ = cancel_up.notified() => break,
                r = tokio::time::timeout(BRIDGE_READ_TIMEOUT, c_read.read(&mut buf)) => match r {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    _ => break,
                },
            };
            let chunk = &mut buf[..n];
            STATS.bytes_up.fetch_add(n as i64, Ordering::Relaxed);
            clt_dec_up.lock().await.xor(chunk);
            tg_enc_up.lock().await.xor(chunk);
            if r_write.write_all(chunk).await.is_err() {
                break;
            }
            client_sent_up.store(true, Ordering::Relaxed);
        }
        cancel_up.notify_waiters();
    };

    let cancel_down = cancel.clone();
    let cancel_token_down = cancel_token.clone();
    let tg_dec_down = tg_dec.clone();
    let clt_enc_down = clt_enc.clone();
    let got_down_down = got_downstream.clone();
    let down = async move {
        let mut buf = vec![0u8; 131072];
        loop {
            let n = tokio::select! {
                _ = cancel_token_down.cancelled() => break,
                _ = cancel_down.notified() => break,
                r = tokio::time::timeout(BRIDGE_READ_TIMEOUT, r_read.read(&mut buf)) => match r {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    _ => break,
                },
            };
            let chunk = &mut buf[..n];
            STATS.bytes_down.fetch_add(n as i64, Ordering::Relaxed);
            got_down_down.store(true, Ordering::Relaxed);
            tg_dec_down.lock().await.xor(chunk);
            clt_enc_down.lock().await.xor(chunk);
            if c_write.write_all(chunk).await.is_err() {
                break;
            }
        }
        cancel_down.notify_waiters();
    };

    let cancel_wd = cancel.clone();
    let cancel_token_wd = cancel_token.clone();
    let sent_wd = client_sent.clone();
    let got_wd = got_downstream.clone();
    let stalled_wd = stalled.clone();
    let watchdog = async move {
        let mut first_sent: Option<std::time::Instant> = None;
        let mut ticker = tokio::time::interval(BRIDGE_WATCHDOG_INTERVAL);
        loop {
            tokio::select! {
                _ = cancel_token_wd.cancelled() => return,
                _ = cancel_wd.notified() => return,
                _ = ticker.tick() => {
                    if got_wd.load(Ordering::Relaxed) {
                        return;
                    }
                    if sent_wd.load(Ordering::Relaxed) {
                        let since = *first_sent.get_or_insert_with(std::time::Instant::now);
                        if since.elapsed() >= BRIDGE_FIRST_DOWNSTREAM_TIMEOUT {
                            stalled_wd.store(true, Ordering::Relaxed);
                            lwarn!(" TCP-туннель: нет ответа от Telegram {:.0}с — закрываю", since.elapsed().as_secs_f64());
                            cancel_wd.notify_waiters();
                            return;
                        }
                    }
                }
            }
        }
    };

    tokio::join!(up, down, watchdog);
    let _ = (clt_dec, clt_enc, tg_enc, tg_dec);
    stalled.load(Ordering::Relaxed)
}

pub async fn bridge_tcp_stream(
    client: TcpStream,
    remote: TcpStream,
    clt_dec: TrackedStream,
    clt_enc: TrackedStream,
    tg_enc: TrackedStream,
    tg_dec: TrackedStream,
    cancel_token: CancellationToken,
) {
    let (c_read, c_write) = tokio::io::split(client);
    let _ = bridge_tcp(
        c_read,
        c_write,
        remote,
        clt_dec,
        clt_enc,
        tg_enc,
        tg_dec,
        cancel_token,
    )
    .await;
}

// ---------------------------------------------------------------------------
// TCP fallback — порт bridge._tcp_fallback
// ---------------------------------------------------------------------------

pub async fn tcp_fallback<R, W>(
    conn_read: R,
    conn_write: W,
    dst: &str,
    port: u16,
    init: &[u8],
    label: String,
    ctx_streams: (TrackedStream, TrackedStream, TrackedStream, TrackedStream),
    cancel_token: CancellationToken,
) -> bool
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let addr = format!("{}:{}", dst, port);
    let mut remote = match crate::net::outbound_tcp(&addr, Duration::from_secs(10)).await {
        Ok(r) => r,
        Err(e) => {
            lwarn!("[{}] TCP fallback to {}:{} failed: {}", label, dst, port, e);
            return false;
        }
    };
    let _ = remote.set_nodelay(true);

    STATS.connections_tcp_fallback.fetch_add(1, Ordering::Relaxed);
    if remote.write_all(init).await.is_err() {
        return false;
    }
    let (clt_dec, clt_enc, tg_enc, tg_dec) = ctx_streams;
    let stalled = bridge_tcp(
        conn_read,
        conn_write,
        remote,
        clt_dec,
        clt_enc,
        tg_enc,
        tg_dec,
        cancel_token,
    )
    .await;
    if stalled {
        // Прямой TCP до DC «соединился», но ответа нет: DPI/блокировка.
        // Помечаем IP, чтобы следующие соединения не залипали на нём.
        let now = now_monotonic();
        IP_FAIL_UNTIL
            .write()
            .insert(dst.to_string(), now + IP_FAIL_COOLDOWN);
        lwarn!(
            "[{}] TCP fallback {}:{} без downstream -> IP в cooldown",
            label, dst, port
        );
    }
    true
}

// ---------------------------------------------------------------------------
// Cfproxy fallback — мобильная версия (параллель + 429 cooldown + DoH),
// путь и secure как в оригинале.
// ---------------------------------------------------------------------------

async fn try_cfproxy_base_domain(
    dc: i32,
    base_domain: &str,
    ws_path: &str,
    ignore_fail_cooldown: bool,
) -> (Option<RawWebSocket>, String) {
    // Домены в пуле уже каноникализированы (пользовательские — как есть,
    // encoded-записи — декодированы). Никакого повторного decode!
    let base_domain = base_domain.trim().trim_end_matches('.').to_lowercase();
    if base_domain.is_empty() || !is_valid_domain(&base_domain) {
        return (None, String::new());
    }
    let remaining = cfproxy_429_cooldown_remaining(&base_domain);
    if remaining > Duration::ZERO {
        ldebug!(
            " CF skip {}: 429 cooldown {:.0}s",
            base_domain,
            remaining.as_secs_f64().ceil()
        );
        return (None, String::new());
    }
    if !ignore_fail_cooldown {
        let fail_remaining = domain_fail_remaining(&base_domain);
        if fail_remaining > Duration::ZERO {
            ldebug!(
                " CF skip {}: health cooldown {:.0}s",
                base_domain,
                fail_remaining.as_secs_f64().ceil()
            );
            return (None, String::new());
        }
    }
    let _permit = match acquire_cfproxy_attempt_slot().await {
        Some(p) => p,
        None => return (None, String::new()),
    };

    let domain = format!("kws{}.{}", dc, base_domain);
    ldebug!(" CF try {}", domain);

    let (ws, resolved_ip, err) = cf_connect_domain(&domain, ws_path, 5.0).await;
    if let Some(e) = err {
        // 429 — это лимит конкретного домена, а не блокировка Cloudflare,
        // поэтому предохранитель не трогаем.
        if is_http_status_error(&e, 429) {
            mark_cfproxy_429_cooldown(&base_domain, &e);
        } else {
            if matches!(e, WsError::Timeout) || matches!(e, WsError::Io(_)) {
                cf_circuit_note_failure();
            }
            // Health-кулдаун на любые ошибки: мёртвый домен быстро выпадает
            // из активной ротации и возвращается с эскалирующейся паузой.
            mark_domain_fail(&base_domain);
        }
        if !resolved_ip.is_empty() {
            log_cf_conn_error(
                &format!(" CF fail {} via {}: {}", domain, resolved_ip, e.compact()),
                &e,
            );
        } else {
            log_cf_conn_error(&format!(" CF fail {}: {}", domain, e.compact()), &e);
        }
        return (None, String::new());
    }

    clear_cfproxy_429_cooldown(&base_domain);
    clear_domain_fail(&base_domain);
    cf_circuit_note_success();
    if !resolved_ip.is_empty() {
        ldebug!(" CF ok {} via {}", domain, resolved_ip);
    } else {
        ldebug!(" CF ok {} via hostname", domain);
    }
    (ws, base_domain)
}

// Только устанавливает WS-соединение через CF, НЕ трогая conn.
async fn cfproxy_acquire_ws(
    dc: i32,
    is_media: bool,
    ws_path: &str,
    cancel_token: &CancellationToken,
) -> Option<(RawWebSocket, String)> {
    let (enabled, domains) = {
        let cfg = CFPROXY.read();
        (
            CFPROXY_ENABLED.load(Ordering::Relaxed),
            cfg.domains.clone(),
        )
    };
    if !enabled || domains.is_empty() {
        return None;
    }

    let ordered = crate::balancer::BALANCER.read().get_domains_for_dc(dc);
    if ordered.is_empty() {
        return None;
    }

    let m_tag = if is_media { " media" } else { "" };
    ldebug!(" CF fallback DC{}{}: {} домен(ов)", dc, m_tag, ordered.len());

    let mut ws: Option<RawWebSocket> = None;
    let mut chosen_domain = String::new();

    if !ordered.is_empty() && !ordered[0].is_empty() {
        let (w, d) = try_cfproxy_base_domain(dc, &ordered[0], ws_path, false).await;
        ws = w;
        chosen_domain = d;
    }

    if ws.is_none() && ordered.len() > 1 {
        let remaining_domains: Vec<String> = ordered[1..].to_vec();
        let sem = Arc::new(tokio::sync::Semaphore::new(CFPROXY_FALLBACK_PARALLEL));
        let mut handles = Vec::new();
        for bd in remaining_domains {
            let sem = sem.clone();
            let cancel = cancel_token.clone();
            let ws_path = ws_path.to_string();
            handles.push(tokio::spawn(async move {
                tokio::select! {
                    _ = cancel.cancelled() => None,
                    r = async {
                        let _p = sem.acquire().await.ok()?;
                        let (w, d) = try_cfproxy_base_domain(dc, &bd, &ws_path, false).await;
                        w.map(|ws| (ws, d))
                    } => r,
                }
            }));
        }
        for h in handles {
            if let Ok(Some((w, d))) = h.await {
                if ws.is_none() {
                    ws = Some(w);
                    chosen_domain = d;
                } else {
                    tokio::spawn(async move {
                        w.close().await;
                    });
                }
            }
        }
    }

    // Если всё в health-кулдауне (например, после смены сети) — одна
    // принудительная попытка для доменов с минимальным остатком кулдауна.
    if ws.is_none() {
        let cooled: Vec<String> = ordered
            .iter()
            .filter(|d| domain_fail_remaining(d) > Duration::ZERO)
            .cloned()
            .take(CFPROXY_FALLBACK_PARALLEL)
            .collect();
        if !cooled.is_empty() {
            ldebug!(" CF: все домены в cooldown, форсирую {}", cooled.len());
        }
        for bd in cooled {
            if ws.is_some() {
                break;
            }
            let (w, d) = try_cfproxy_base_domain(dc, &bd, ws_path, true).await;
            if w.is_some() {
                ws = w;
                chosen_domain = d;
            }
        }
    }

    match ws {
        Some(w) => {
            if !chosen_domain.is_empty() {
                if crate::balancer::BALANCER.write().update_domain_for_dc(dc, &chosen_domain) {
                    linfo!(" CF домен для DC{} -> {}", dc, chosen_domain);
                }
            }
            Some((w, chosen_domain))
        }
        None => {
            if log_once_per("cf-all-domains-down", 20) {
                lwarn!(
                    " CF fallback DC{}{}: все CF домены недоступны (маршрут помечен, повторы в логе подавлены)",
                    dc, m_tag
                );
            } else {
                ldebug!(" CF fallback DC{}{}: все CF домены недоступны", dc, m_tag);
            }
            None
        }
    }
}

// ---------------------------------------------------------------------------
// doFallback — порт bridge.do_fallback: cf_worker -> cf -> tcp.
// CF не "съедает" conn при провале: тот же conn уходит в TCP fallback.
// halves передаются дальше только в успешную ветвь: worker-ws и cf-ws
// добываются БЕЗ halves, затем halves уходят в bridge/tcp.
// ---------------------------------------------------------------------------

pub async fn do_fallback<R, W>(
    pools: &ProxyPools,
    conn_read: R,
    conn_write: W,
    relay_init: &[u8],
    label: String,
    dc: i32,
    is_test: bool,
    is_media: bool,
    splitter: Option<MsgSplitter>,
    clt_dec: &TrackedStream,
    clt_enc: &TrackedStream,
    tg_enc: &TrackedStream,
    tg_dec: &TrackedStream,
    cancel_token: CancellationToken,
) -> bool
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let m_tag = if is_media { " media" } else { "" };
    let fallback_dst = resolve_fallback_target(dc, is_media, is_test);
    let cf_enabled = CFPROXY_ENABLED.load(Ordering::Relaxed) && !is_test;
    // Предохранитель: если CF-домены отваливаются подряд (типично при
    // блокировке Cloudflare у провайдера), не тратим по 5 с на каждый домен
    // в каждом соединении — временно пропускаем маршрут целиком.
    let cf_circuit = cf_circuit_open();
    if cf_circuit && cf_enabled && log_once_per("cf-circuit-skip", 30) {
        lwarn!(" CF: маршрут Cloudflare временно пропущен (серия неудач), идём другим путём");
    }
    let use_cf = cf_enabled && !cf_circuit;
    let worker_domains = CF_WORKER_DOMAINS.read().clone();
    let ws_path = ws_path_for(is_test);
    // TCP fallback идёт напрямую в DC Telegram: 443 — единственный реально
    // рабочий порт (80 там не слушает MTProto).
    let secure_port: u16 = 443;
    let use_worker = !worker_domains.is_empty() && !fallback_dst.is_empty() && !is_test;

    // Шаг 1: worker-ws (без halves) — порт _cfproxy_worker_fallback.
    if use_worker {
        let pooled = pools
            .cf_worker
            .get(dc, fallback_dst.clone(), worker_domains.clone())
            .await;
        let mut used_worker_domain = String::new();
        let worker_ws = if let Some((ws, worker_domain)) = pooled {
            linfo!(
                "[{}] DC{}{} -> CF worker pool hit via {} for {}",
                label, dc, m_tag, worker_domain, fallback_dst
            );
            used_worker_domain = worker_domain;
            Some(ws)
        } else {
            // Workers.dev на порту 80 отвечает редиректом на HTTPS, поэтому
            // для своего воркера всегда используем wss:// (443).
            let secure = true;
            let query = format!("dst={}&dc={}", fallback_dst, dc);
            let path = format!("/apiws?{}", query);
            let mut found = None;
            for worker_domain in pools.cf_worker.available_domains(worker_domains.clone()).await {
                linfo!(
                    "[{}] DC{}{} -> trying CF worker {} for {}",
                    label, dc, m_tag, worker_domain, fallback_dst
                );
                let mut worker_result: Option<RawWebSocket> = None;
                let mut last_exc = None;
                for secure_try in [secure, !secure] {
                    match ws_connect_full_opts(
                        &worker_domain,
                        &worker_domain,
                        &path,
                        10.0,
                        None,
                        Some(secure_try),
                    )
                    .await
                    {
                        Ok(ws) => {
                            worker_result = Some(ws);
                            break;
                        }
                        Err(exc) => {
                            // Ошибку запоминаем только после последней попытки:
                            // воркер мог просто не отвечать на первом порту.
                            last_exc = Some(exc);
                        }
                    }
                }
                match worker_result {
                    Some(ws) => {
                        used_worker_domain = worker_domain.clone();
                        found = Some(ws);
                        break;
                    }
                    None => {
                        if let Some(exc) = last_exc {
                            pools.cf_worker.report_failure(&worker_domain, &exc).await;
                            lwarn!(
                                "[{}] DC{}{} CF worker {} failed: {}",
                                label, dc, m_tag, worker_domain, exc.compact()
                            );
                        }
                    }
                }
            }
            found
        };
        if let Some(ws) = worker_ws {
            STATS.connections_cfproxy.fetch_add(1, Ordering::Relaxed);
            if ws.send(relay_init).await.is_ok() {
                let outcome = bridge_ws(
                    conn_read,
                    conn_write,
                    ws,
                    label,
                    dc,
                    is_media,
                    None, // оригинал: splitter=None для worker
                    clt_dec.clone_state(),
                    clt_enc.clone_state(),
                    tg_enc.clone_state(),
                    tg_dec.clone_state(),
                    cancel_token,
                )
                .await;
                if outcome.stalled {
                    // Worker отдал 101, но MTProto через него не пошёл —
                    // уводим этот worker в cooldown, чтобы не залипать.
                    mark_domain_fail(&used_worker_domain);
                    lwarn!(
                        " DC{}{} worker {} без downstream — в cooldown",
                        dc, m_tag, used_worker_domain
                    );
                }
                return true;
            }
            ws.close().await;
            // send failed — падаем сквозь к CF/TCP на тех же halves.
        }
    }

    // Шаг 2: cf-ws (без halves).
    if use_cf {
        if let Some((ws, chosen_domain)) =
            cfproxy_acquire_ws(dc, is_media, ws_path, &cancel_token).await
        {
            STATS.connections_cfproxy.fetch_add(1, Ordering::Relaxed);
            linfo!(" DC{}{} подключен через CF", dc, m_tag);

            if ws.send(relay_init).await.is_ok() {
                let outcome = bridge_ws(
                    conn_read,
                    conn_write,
                    ws,
                    label,
                    dc,
                    is_media,
                    splitter,
                    clt_dec.clone_state(),
                    clt_enc.clone_state(),
                    tg_enc.clone_state(),
                    tg_dec.clone_state(),
                    cancel_token,
                )
                .await;
                if outcome.stalled {
                    mark_domain_fail(&chosen_domain);
                    lwarn!(
                        " DC{}{} CF {} без downstream — домен в cooldown",
                        dc, m_tag, chosen_domain
                    );
                }
                return true;
            }
            ws.close().await;
            // CF умер сразу после хендшейка — пробуем TCP на том же conn.
        }
        // CF не дал ws — halves НЕ тронуты, идём в TCP fallback ниже.
    }

    // Шаг 3: tcp.
    if !fallback_dst.is_empty() {
        linfo!(
            "[{}] DC{}{} -> TCP fallback to {}:{}",
            label, dc, m_tag, fallback_dst, secure_port
        );
        return tcp_fallback(
            conn_read,
            conn_write,
            &fallback_dst,
            secure_port,
            relay_init,
            label,
            (
                clt_dec.clone_state(),
                clt_enc.clone_state(),
                tg_enc.clone_state(),
                tg_dec.clone_state(),
            ),
            cancel_token,
        )
        .await;
    }

    false
}

// ---------------------------------------------------------------------------
// Client serving — порт tg_ws_proxy._handle_client (dd + ee/FakeTLS).
// ---------------------------------------------------------------------------

async fn read_proxy_protocol_line(conn: &mut TcpStream) -> Option<String> {
    let mut line = Vec::with_capacity(108);
    let mut byte = [0u8; 1];
    let res = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let n = conn.read(&mut byte).await.map_err(|_| ())?;
            if n == 0 {
                return Err(());
            }
            line.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
            if line.len() > 108 {
                break;
            }
        }
        Ok::<(), ()>(())
    })
    .await;
    match res {
        Ok(Ok(())) => Some(String::from_utf8_lossy(&line).to_string()),
        _ => None,
    }
}

pub async fn handle_client(
    pools: Arc<ProxyPools>,
    mut conn: TcpStream,
    cancel_token: CancellationToken,
) {
    STATS.connections_total.fetch_add(1, Ordering::Relaxed);
    STATS.connections_active.fetch_add(1, Ordering::Relaxed);
    struct ActiveGuard;
    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            if STATS.connections_active.load(Ordering::Relaxed) > 0 {
                STATS.connections_active.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
    let _guard = ActiveGuard;

    let peer = conn
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let mut label = peer;

    let _ = conn.set_nodelay(true);

    let current_secret = PROXY_SECRET.read().clone();
    let secret_bytes = hex::decode(&current_secret).unwrap_or_default();

    // PROXY protocol (proxy_config.proxy_protocol в оригинале).
    if PROXY_PROTOCOL.load(Ordering::Relaxed) {
        match read_proxy_protocol_line(&mut conn).await {
            Some(line) => {
                let text = line.trim().to_string();
                if text.starts_with("PROXY ") {
                    let parts: Vec<&str> = text.split_whitespace().collect();
                    if parts.len() >= 6 {
                        label = format!("{}:{}", parts[2], parts[4]);
                    }
                    ldebug!("[{}] PROXY protocol: {}", label, text);
                } else {
                    ldebug!("[{}] expected PROXY header, got: {:?}", label, &text[..text.len().min(60)]);
                }
            }
            None => {
                ldebug!("[{}] disconnected during PROXY header", label);
                return;
            }
        }
    }

    // FakeTLS (ee-secret): первый байт решает всё — как _read_client_init.
    let masking = FAKE_TLS_DOMAIN.read().clone();
    if !masking.is_empty() {
        let mut first = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut first)).await
        {
            Ok(Ok(_)) => {}
            _ => {
                ldebug!("[{}] client disconnected before handshake", label);
                return;
            }
        }
        if first[0] == faketls::TLS_RECORD_HANDSHAKE {
            match faketls::server_handshake(conn, first[0], &secret_bytes, &masking, &label).await
            {
                Some(plain) => {
                    serve_core(
                        &pools,
                        plain.read,
                        plain.write,
                        label,
                        secret_bytes,
                        cancel_token,
                    )
                    .await;
                }
                None => {}
            }
            return;
        } else {
            ldebug!("[{}] non-TLS byte 0x{:02X} -> HTTP redirect", label, first[0]);
            let redirect = format!(
                "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                masking
            );
            let _ = conn.write_all(redirect.as_bytes()).await;
            return;
        }
    }

    let (conn_read, conn_write) = tokio::io::split(conn);
    serve_core(
        &pools,
        conn_read,
        conn_write,
        label,
        secret_bytes,
        cancel_token,
    )
    .await;
}

/// Ядро обслуживания соединения: 64-байтный handshake → маршрут → bridge.
/// Generic над транспортом (TcpStream-halves или FakeTLS-duplex-halves).
async fn serve_core<R, W>(
    pools: &ProxyPools,
    mut conn_read: R,
    mut conn_write: W,
    label: String,
    secret_bytes: Vec<u8>,
    cancel_token: CancellationToken,
) where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    // 64-байтный handshake
    let mut handshake = [0u8; 64];
    match tokio::time::timeout(Duration::from_secs(10), conn_read.read_exact(&mut handshake)).await
    {
        Ok(Ok(_)) => {}
        _ => {
            ldebug!("[{}] client disconnected before handshake", label);
            return;
        }
    }
    // Первый байт нужен для диагностики после расшифровки (handshake ниже
    // перемещается в decrypted): 0x16 = TLS ClientHello = старая ee-ссылка.
    let first_byte = handshake[0];

    if is_http_transport(&handshake) {
        STATS.connections_http_reject.fetch_add(1, Ordering::Relaxed);
        let _ = conn_write
            .write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")
            .await;
        let _ = conn_write.shutdown().await;
        return;
    }

    // _try_handshake: key = SHA256(prekey + secret).
    //
    // Перебираем активный секрет и недавние: если в Telegram осталась ссылка
    // со старым секретом, прокси всё равно примет подключение вместо того,
    // чтобы бесконечно отвечать «bad handshake».
    let clt_dec_prekey = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
    let clt_dec_iv = &handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];

    let mut decrypted = handshake;
    let mut proto = 0u32;
    let mut matched_secret: Option<Vec<u8>> = None;
    let mut matched_plain = false;

    // 1) secure-режим (ссылка с префиксом dd): расшифровываем кандидатами.
    for (_cand, cand_bytes) in secret_candidates() {
        let mut hash_dec = Sha256::new();
        hash_dec.update(clt_dec_prekey);
        hash_dec.update(&cand_bytes);
        let mut decryptor = new_aes_ctr(&hash_dec.finalize(), clt_dec_iv);
        let mut attempt = decrypted;
        decryptor.xor(&mut attempt);
        let p = LittleEndian::read_u32(&attempt[PROTO_TAG_POS..PROTO_TAG_POS + 4]);
        if valid_proto(p) {
            decrypted = attempt;
            proto = p;
            matched_secret = Some(cand_bytes);
            break;
        }
    }

    // 2) simple-режим (секрет без префикса dd): первые 4 байта — открытый
    //    proto tag. Так работают ссылки вида tg://proxy?secret=<hex>.
    if matched_secret.is_none() {
        let p = LittleEndian::read_u32(&handshake[0..4]);
        if valid_proto(p) {
            proto = p;
            matched_plain = true;
            ldebug!("[{}] handshake в simple-режиме (секрет без dd)", label);
        }
    }

    if !valid_proto(proto) {
        STATS.connections_bad.fetch_add(1, Ordering::Relaxed);
        BAD_HANDSHAKES_TOTAL.fetch_add(1, Ordering::Relaxed);
        // Telegram ретраит подключение постоянно, поэтому без ограничения
        // лог превращался в бесконечный спам. Пишем не чаще раза в 10 секунд
        // и сообщаем, сколько повторов скрыто.
        if let Some(suppressed) = bad_handshake_log_gate(10) {
            let hint = if PROXY_SECRET.read().as_str() == "00000000000000000000000000000000" {
                "прокси запущен без секрета"
            } else if first_byte == faketls::TLS_RECORD_HANDSHAKE {
                "клиент прислал FakeTLS ClientHello: в Telegram осталась старая ee-ссылка"
            } else {
                "секрет в Telegram не совпадает с активным"
            };
            if suppressed > 0 {
                lwarn!(
                    "[{}] bad handshake ({}): ещё {} попыток за последние 10 с скрыто. Перепримените ссылку из приложения",
                    label, hint, suppressed
                );
            } else {
                lwarn!(
                    "[{}] bad handshake ({}). Перепримените ссылку из приложения: Настройки/Главная -> «Применить в Telegram»",
                    label, hint
                );
            }
        }
        // Мгновенный разрыв Telegram воспринимает как «прокси перегружен»
        // и открывает соединения заново без паузы (в логах была тысяча
        // попыток за 10 секунд). Держим сокет открытым, чтобы клиент
        // отступал с задержкой и не устраивал шторм.
        tokio::time::sleep(Duration::from_millis(700)).await;
        return;
    }

    let plain_mode = matched_plain;
    let effective_secret = matched_secret.clone().unwrap_or_else(|| secret_bytes.clone());

    // В secure-режиме proto tag и DC лежат в конце расшифрованного заголовка,
    // в simple-режиме — в открытом начале (первые 6 байт).
    let (proto_bytes, dc_field): ([u8; 4], [u8; 2]) = if plain_mode {
        (
            [handshake[0], handshake[1], handshake[2], handshake[3]],
            [handshake[4], handshake[5]],
        )
    } else {
        let mut p = [0u8; 4];
        p.copy_from_slice(&decrypted[PROTO_TAG_POS..PROTO_TAG_POS + 4]);
        let mut d = [0u8; 2];
        d.copy_from_slice(&decrypted[DC_IDX_POS..DC_IDX_POS + 2]);
        (p, d)
    };
    let dc_raw = LittleEndian::read_u16(&dc_field) as i16;
    let mut dc = dc_raw as i32;
    if dc < 0 {
        dc = -dc;
    }
    let is_media = dc_raw < 0;

    // Test DC: proxy_config.force_test_dc или dc >= 10000.
    let mut is_test_dc = FORCE_TEST_DC.load(Ordering::Relaxed) || dc >= 10000;
    if dc >= 10000 {
        linfo!("[{}] test DC{} -> DC{}", label, dc, dc - 10000);
        dc -= 10000;
    }
    // force_test_dc тянет весь трафик на тестовые IP/путь.
    if FORCE_TEST_DC.load(Ordering::Relaxed) {
        is_test_dc = true;
    }
    let m_tag = if is_media { " media" } else { "" };

    let proto_int = proto; // u32 tag; MsgSplitter маппит через proto_tag_to_type
    let dc_idx = if is_media { -dc } else { dc };

    ldebug!(
        "[{}] handshake ok: DC{}{} proto=0x{:08X}{}",
        label,
        dc,
        m_tag,
        proto_int,
        if is_test_dc { " test" } else { "" }
    );

    let mut relay_init = [0u8; 64];
    let mut clt_decryptor;
    let mut clt_encryptor;
    let mut tg_encryptor;
    let mut tg_decryptor;

    if plain_mode {
        // simple-режим: заголовок клиента уходит в DC как есть, шифрования нет.
        relay_init.copy_from_slice(&handshake);
        clt_decryptor = TrackedStream::new_plain();
        clt_encryptor = TrackedStream::new_plain();
        tg_encryptor = TrackedStream::new_plain();
        tg_decryptor = TrackedStream::new_plain();
    } else {
        // relayInit генерация (1-в-1 c Go + RESERVED из utils.py).
        loop {
            rand::thread_rng().fill_bytes(&mut relay_init);
            if relay_init[0] == RESERVED_FIRST_BYTE {
                continue;
            }
            if is_reserved_start(&relay_init[..4]) {
                continue;
            }
            if relay_init[4] == 0 && relay_init[5] == 0 && relay_init[6] == 0 && relay_init[7] == 0 {
                continue;
            }
            break;
        }

        let mut tg_dec_prekey_and_iv = [0u8; 48];
        for i in 0..48 {
            tg_dec_prekey_and_iv[i] = relay_init[8 + 47 - i];
        }

        tg_encryptor = new_aes_ctr(&relay_init[8..40], &relay_init[40..56]);
        tg_decryptor = new_aes_ctr(&tg_dec_prekey_and_iv[..32], &tg_dec_prekey_and_iv[32..]);

        let mut dc_bytes = [0u8; 2];
        LittleEndian::write_u16(&mut dc_bytes, dc_idx as u16);

        let mut tail_plain = [0u8; 8];
        tail_plain[0..4].copy_from_slice(&proto_bytes);
        tail_plain[4..6].copy_from_slice(&dc_bytes);
        rand::thread_rng().fill_bytes(&mut tail_plain[6..8]);

        let mut encrypted_full = relay_init;
        tg_encryptor.xor(&mut encrypted_full);

        let mut keystream_tail = [0u8; 8];
        for i in 0..8 {
            keystream_tail[i] = encrypted_full[56 + i] ^ relay_init[56 + i];
            relay_init[56 + i] = tail_plain[i] ^ keystream_tail[i];
        }

        // clt_decryptor: тот же ключ, что и у клиента; прокручиваем ровно
        // 64 байта, которые клиент уже потратил на свой хендшейк.
        let mut hash_dec = Sha256::new();
        hash_dec.update(clt_dec_prekey);
        hash_dec.update(&effective_secret);
        clt_decryptor = new_aes_ctr(&hash_dec.finalize(), clt_dec_iv);
        let mut scratch = [0u8; 64];
        clt_decryptor.xor(&mut scratch);

        // clt_encryptor: prekey/iv = reverse(client_dec_prekey_iv), key=SHA256+secret.
        let mut clt_enc_prekey_and_iv = [0u8; 48];
        for i in 0..48 {
            clt_enc_prekey_and_iv[i] = handshake[8 + 47 - i];
        }
        let mut hash_enc = Sha256::new();
        hash_enc.update(&clt_enc_prekey_and_iv[..32]);
        hash_enc.update(&effective_secret);
        clt_encryptor = new_aes_ctr(&hash_enc.finalize(), &clt_enc_prekey_and_iv[32..]);
    }

    let dc_key = DcKey::new(dc, is_media, is_test_dc);
    let now = now_monotonic();
    let ws_path = ws_path_for(is_test_dc);

    let target_opt = resolve_configured_target(dc, is_media);
    let dc_configured = target_opt.is_some();
    let target = target_opt.unwrap_or_default();

    let blacklisted = WS_BLACKLIST.read().get(&dc_key).copied().unwrap_or(false);
    let ip_cooldown_active = if target.is_empty() {
        false
    } else {
        IP_FAIL_UNTIL.read().get(&target).map(|until| now < *until).unwrap_or(false)
    };
    // Свой Cloudflare Worker — самый предсказуемый маршрут (личные лимиты,
    // нет общих 429). Если он настроен, идём в fallback сразу, не дожидаясь,
    // пока прямой WS «полуподключится» и зависнет.
    let has_own_worker = !CF_WORKER_DOMAINS.read().is_empty();
    let prefer_worker = has_own_worker && !is_test_dc;
    let is_any_cf_fallback =
        CFPROXY_ENABLED.load(Ordering::Relaxed) || has_own_worker;

    // Раньше при «авто»-режиме DC (пустой DC→IP конфиг) прямой WS вообще не
    // пробовался: каждое соединение сразу уходило в fallback (CF → TCP), и
    // если пул CF недоступен, не работал ни один маршрут. Теперь прямой WS
    // пробуется всегда: при пустом target соединение идёт по имени
    // kws{dc}.web.telegram.org с DoH-резолвом.
    let mut pooled_ws: Option<RawWebSocket> = None;
    let mut use_pooled_direct = false;
    if blacklisted || (ip_cooldown_active && is_any_cf_fallback) || prefer_worker {
        if prefer_worker && dc_configured && !blacklisted {
            linfo!(
                "[{}] DC{}{} -> свой Cloudflare Worker (приоритет)",
                label, dc, m_tag
            );
        } else if blacklisted {
            linfo!("[{}] DC{}{} WS blacklisted -> fallback", label, dc, m_tag);
        } else {
            // Шанс пулу при случайном таймауте: пробуем забрать готовый WS.
            if !is_test_dc {
                let domains = ws_domains(dc, is_media);
                pooled_ws = pools
                    .ws
                    .get(dc, is_media, target.clone(), domains)
                    .await;
            }
            if pooled_ws.is_none() {
                linfo!(
                    "[{}] DC{}{} WS connect to {} was timed out -> fallback",
                    label, dc, m_tag, target
                );
            } else {
                linfo!(
                    "[{}] DC{}{} WS connect to {} was timed out, but pool hit -> using WS",
                    label, dc, m_tag, target
                );
                use_pooled_direct = true;
            }
        }

        if !use_pooled_direct {
            let splitter = MsgSplitter::new(&relay_init, proto_int);
            let ok = do_fallback(
                pools,
                conn_read,
                conn_write,
                &relay_init,
                label.clone(),
                dc,
                is_test_dc,
                is_media,
                splitter,
                &clt_decryptor,
                &clt_encryptor,
                &tg_encryptor,
                &tg_decryptor,
                cancel_token,
            )
            .await;
            if !ok {
                lwarn!("[{}] DC{}{} no fallback available", label, dc, m_tag);
            }
            return;
        }
    }

    let fail_until = DC_FAIL_UNTIL.read().get(&dc_key).copied().unwrap_or(0.0);
    let ws_timeout = if now < fail_until {
        WS_FAIL_TIMEOUT
    } else {
        WS_DIRECT_TIMEOUT
    };

    let domains = ws_domains(dc, is_media);
    // pooled_ws уже может держать WS из cooldown-ветки.
    let mut ws_opt = pooled_ws;
    let mut ws_failed_redirect = false;
    let mut ws_timed_out = false;
    let mut all_redirects = true;

    if ws_opt.is_none() && !is_test_dc {
        ws_opt = pools
            .ws
            .get(dc, is_media, target.clone(), domains.clone())
            .await;
        if ws_opt.is_some() {
            linfo!("[{}] DC{}{} -> pool hit via {}", label, dc, m_tag, target);
        }
    }

    if ws_opt.is_none() {
        if target.is_empty() {
            ldebug!(
                "[{}] DC{}{}: прямой WS по имени (авто-режим DC)",
                label, dc, m_tag
            );
        }
        for domain in &domains {
            let url = format!("wss://{}{} via {}", domain, ws_path, target);
            linfo!("[{}] DC{}{} -> {}", label, dc, m_tag, url);
            // Прямой WS к kws{dc}.web.telegram.org всегда по TLS (443).
            match ws_connect_full_opts(&target, domain, ws_path, ws_timeout, None, Some(true)).await {
                Ok(ws) => {
                    all_redirects = false;
                    ws_opt = Some(ws);
                    break;
                }
                Err(WsError::Handshake(h)) if h.is_redirect() => {
                    STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                    ws_failed_redirect = true;
                    lwarn!(
                        "[{}] DC{}{} got {} from {} -> {}",
                        label,
                        dc,
                        m_tag,
                        h.status_code,
                        domain,
                        if h.location.is_empty() { "?" } else { &h.location }
                    );
                    continue;
                }
                Err(WsError::Handshake(h)) => {
                    STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                    all_redirects = false;
                    lwarn!(
                        "[{}] DC{}{} WS handshake: {}",
                        label, dc, m_tag, h.status_line
                    );
                    continue;
                }
                Err(WsError::Timeout) => {
                    STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                    ws_timed_out = true;
                    lwarn!(
                        "[{}] DC{}{} WS connect timed out via {}",
                        label, dc, m_tag, domain
                    );
                    break;
                }
                Err(exc) => {
                    STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                    all_redirects = false;
                    lwarn!(
                        "[{}] DC{}{} WS connect failed: {}",
                        label, dc, m_tag, exc.compact()
                    );
                    continue;
                }
            }
        }
    } else {
        all_redirects = false;
    }

    // WS failed -> fallback (порт оригинала 1-в-1).
    if ws_opt.is_none() {
        if ws_timed_out && !target.is_empty() {
            IP_FAIL_UNTIL
                .write()
                .insert(target.clone(), now + IP_FAIL_COOLDOWN);
            linfo!(
                "[{}] DC{}{} WS connect to {} timed out, cooldown for {}s",
                label, dc, m_tag, target, IP_FAIL_COOLDOWN as i64
            );
        }

        if ws_failed_redirect && all_redirects {
            WS_BLACKLIST.write().insert(dc_key, true);
            lwarn!("[{}] DC{}{} blacklisted for WS (all 302)", label, dc, m_tag);
        } else if ws_failed_redirect {
            DC_FAIL_UNTIL.write().insert(dc_key, now + DC_FAIL_COOLDOWN);
        } else {
            DC_FAIL_UNTIL.write().insert(dc_key, now + DC_FAIL_COOLDOWN);
            linfo!(
                "[{}] DC{}{} WS failed for {}s",
                label, dc, m_tag, DC_FAIL_COOLDOWN as i64
            );
        }

        let splitter_fb = MsgSplitter::new(&relay_init, proto_int);
        let ok = do_fallback(
            pools,
            conn_read,
            conn_write,
            &relay_init,
            label.clone(),
            dc,
            is_test_dc,
            is_media,
            splitter_fb,
            &clt_decryptor,
            &clt_encryptor,
            &tg_encryptor,
            &tg_decryptor,
            cancel_token,
        )
        .await;
        if ok {
            linfo!("[{}] DC{}{} fallback closed", label, dc, m_tag);
        }
        return;
    }

    if !target.is_empty() {
        IP_FAIL_UNTIL.write().remove(&target);
    }
    pools.ws.report_success(dc, is_media).await;
    STATS.connections_ws.fetch_add(1, Ordering::Relaxed);

    let splitter = MsgSplitter::new(&relay_init, proto_int);
    if splitter.is_some() {
        ldebug!(
            "[{}] MsgSplitter activated for proto 0x{:08X}",
            label, proto_int
        );
    }

    // send direct init (с retry на свежий WS как мобильное улучшение).
    let mut ws = ws_opt.take().unwrap();
    let mut send_ok = ws.send(&relay_init).await.is_ok();
    if send_ok {
        ldebug!(" direct relayInit sent DC{}{}", dc, m_tag);
    } else {
        lwarn!(" direct relayInit write fail DC{}{}: closed", dc, m_tag);
        ws.close().await;

        DC_FAIL_UNTIL.write().insert(dc_key, now + DC_FAIL_COOLDOWN);

        lwarn!(" direct retry fresh ws DC{}{}", dc, m_tag);
        let (retry_ws, retry_failed_redirect, retry_all_redirects) =
            connect_direct_ws(&target, &domains, ws_timeout, ws_path).await;
        match retry_ws {
            None => {
                if retry_failed_redirect && retry_all_redirects {
                    WS_BLACKLIST.write().insert(dc_key, true);
                    lwarn!(" DC{}{} заблокирован (302)", dc, m_tag);
                }
                lwarn!(" direct fallback DC{}{}", dc, m_tag);
                let splitter_fb = MsgSplitter::new(&relay_init, proto_int);
                do_fallback(
                    pools,
                    conn_read,
                    conn_write,
                    &relay_init,
                    label,
                    dc,
                    is_test_dc,
                    is_media,
                    splitter_fb,
                    &clt_decryptor,
                    &clt_encryptor,
                    &tg_encryptor,
                    &tg_decryptor,
                    cancel_token,
                )
                .await;
                return;
            }
            Some(rws) => {
                if rws.send(&relay_init).await.is_err() {
                    lwarn!(" direct relayInit write fail DC{}{}: closed", dc, m_tag);
                    rws.close().await;
                    lwarn!(" direct fallback DC{}{}", dc, m_tag);
                    let splitter_fb = MsgSplitter::new(&relay_init, proto_int);
                    do_fallback(
                        pools,
                        conn_read,
                        conn_write,
                        &relay_init,
                        label,
                        dc,
                        is_test_dc,
                        is_media,
                        splitter_fb,
                        &clt_decryptor,
                        &clt_encryptor,
                        &tg_encryptor,
                        &tg_decryptor,
                        cancel_token,
                    )
                    .await;
                    return;
                }
                ws = rws;
                send_ok = true;
            }
        }
    }
    let _ = send_ok;

    DC_FAIL_UNTIL.write().remove(&dc_key);
    let outcome = bridge_ws(
        conn_read,
        conn_write,
        ws,
        label.clone(),
        dc,
        is_media,
        splitter,
        clt_decryptor,
        clt_encryptor,
        tg_encryptor,
        tg_decryptor,
        cancel_token,
    )
    .await;
    if outcome.stalled {
        // Прямой WS принял handshake, но данных от DC нет — типичная
        // картина «подключился и вечное Обновление». Помечаем DC/IP
        // упавшими, чтобы следующее соединение ушло на CF/worker/TCP.
        let now2 = now_monotonic();
        DC_FAIL_UNTIL.write().insert(dc_key, now2 + DC_FAIL_COOLDOWN);
        if !target.is_empty() {
            IP_FAIL_UNTIL
                .write()
                .insert(target.clone(), now2 + IP_FAIL_COOLDOWN);
        }
        lwarn!(
            "[{}] DC{}{} прямой WS без downstream -> DC в cooldown",
            label, dc, m_tag
        );
    }
}

// connectDirectWS — прямой перебор доменов (тихий, для retry-пути).
pub async fn connect_direct_ws(
    target: &str,
    domains: &[String],
    timeout: f64,
    ws_path: &str,
) -> (Option<RawWebSocket>, bool, bool) {
    if domains.is_empty() {
        return (None, false, false);
    }
    let mut ws_failed_redirect = false;
    let mut all_redirects = true;

    for dom in domains {
        match ws_connect_full_opts(target, dom, ws_path, timeout, None, Some(true)).await {
            Ok(ws) => return (Some(ws), ws_failed_redirect, false),
            Err(WsError::Handshake(h)) => {
                STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                if h.is_redirect() {
                    ws_failed_redirect = true;
                } else {
                    all_redirects = false;
                }
            }
            Err(WsError::Timeout) => {
                // Как в оригинале: таймаут прерывает перебор, all_redirects не трогаем.
                STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                break;
            }
            Err(_) => {
                STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                all_redirects = false;
            }
        }
    }
    (None, ws_failed_redirect, all_redirects)
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

pub async fn run_proxy(
    pools: Arc<ProxyPools>,
    host: String,
    port: u16,
    dc_opt_map: HashMap<i32, String>,
    cancel_root: CancellationToken,
    listener: TcpListener,
) -> std::io::Result<()> {
    {
        let mut m = DC_OPT.write();
        *m = dc_opt_map.clone();
    }

    start_cfproxy_refresh();

    {
        let p = pools.clone();
        let map = dc_opt_map.clone();
        tokio::spawn(async move {
            p.warmup(&map).await;
        });
    }

    linfo!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    linfo!("  TG WS Proxy запущен");
    linfo!("  Адрес: {}:{}", host, port);
    linfo!("  Target DC IPs:");
    let mut dcs: Vec<i32> = dc_opt_map.keys().copied().collect();
    dcs.sort();
    for dc in dcs {
        if let Some(ip) = dc_opt_map.get(&dc) {
            linfo!("    DC{}: {}", dc, ip);
        }
    }
    if CFPROXY_ENABLED.load(Ordering::Relaxed) {
        linfo!("  CF proxy:      enabled");
    }
    if !CF_WORKER_DOMAINS.read().is_empty() {
        linfo!(
            "  CF worker:     enabled ({})",
            CF_WORKER_DOMAINS.read().join(", ")
        );
    }
    if DISABLE_SECURE.load(Ordering::Relaxed) {
        linfo!("  No secure:     enabled (port 80 for CF proxy/worker)");
    }
    if !FAKE_TLS_DOMAIN.read().is_empty() {
        linfo!("  Fake TLS:      {}", FAKE_TLS_DOMAIN.read().clone());
    }

    let cancel_stats = cancel_root.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            tokio::select! {
                _ = cancel_stats.cancelled() => return,
                _ = interval.tick() => {
                    linfo!(" {}", STATS.summary_ru());
                }
            }
        }
    });

    loop {
        tokio::select! {
            _ = cancel_root.cancelled() => {
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((conn, _)) => {
                        let p = pools.clone();
                        let cancel = cancel_root.child_token();
                        tokio::spawn(async move {
                            handle_client(p, conn, cancel).await;
                        });
                    }
                    Err(_) => {
                        continue;
                    }
                }
            }
        }
    }

    drop(listener);
    cancel_root.cancel();
    tokio::time::sleep(Duration::from_millis(100)).await;
    pools.close_all().await;
    Ok(())
}

pub fn parse_cidr_pool(cidrs_str: &str) -> HashMap<i32, String> {
    let mut result = HashMap::new();
    if cidrs_str.trim().is_empty() {
        return result;
    }
    for pair in cidrs_str.split(',') {
        let parts: Vec<&str> = pair.split(':').collect();
        if parts.len() == 2 {
            let dc_raw = parts[0].trim();
            let ip_raw = parts[1].trim();
            if let Ok(dc) = dc_raw.parse::<i32>() {
                if !ip_raw.is_empty() {
                    if let Ok(ip) = ip_raw.parse::<std::net::IpAddr>() {
                        result.insert(dc, ip.to_string());
                    }
                }
            }
        }
    }
    result
}
