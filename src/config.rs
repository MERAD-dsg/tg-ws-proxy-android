use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Constants & Configuration — портировано из proxy/utils.py + tg_ws_proxy.py
// ---------------------------------------------------------------------------

pub const DEFAULT_PORT: u16 = 1443;
pub const TCP_NODELAY: bool = true;
pub const DEFAULT_RECV_BUF: usize = 256 * 1024;
pub const DEFAULT_SEND_BUF: usize = 256 * 1024;
pub const DEFAULT_POOL_SZ: i32 = 4;

// proxy/tg_ws_proxy.py: IP_FAIL_COOLDOWN / DC_FAIL_COOLDOWN / WS_FAIL_TIMEOUT
pub const IP_FAIL_COOLDOWN: f64 = 3600.0;
pub const DC_FAIL_COOLDOWN: f64 = 60.0;
pub const WS_FAIL_TIMEOUT: f64 = 2.0;
// Прямой WS-коннект при отсутствии cooldown — 5.0 как в оригинале.
// 3 с вместо 5: быстрее переключаемся на резервный маршрут, если прямой
// WS не поднялся. Это заметно уменьшает «залипание» на «Подключении…».
pub const WS_DIRECT_TIMEOUT: f64 = 3.0;

// proxy/utils.py — MTProto handshake layout
pub const HANDSHAKE_LEN: usize = 64;
pub const SKIP_LEN: usize = 8;
pub const PREKEY_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const IV_LEN: usize = 16;
pub const PROTO_TAG_POS: usize = 56;
pub const DC_IDX_POS: usize = 60;

pub const PROTO_TAG_ABRIDGED: u32 = 0xEFEFEFEF;
pub const PROTO_TAG_INTERMEDIATE: u32 = 0xEEEEEEEE;
pub const PROTO_TAG_SECURE: u32 = 0xDDDDDDDD; // padded intermediate

pub const PROTO_ABRIDGED_INT: u32 = 0xEFEFEFEF;
pub const PROTO_INTERMEDIATE_INT: u32 = 0xEEEEEEEE;
pub const PROTO_PADDED_INTERMEDIATE_INT: u32 = 0xDDDDDDDD;

// proxy/utils.py — зарезервированные префиксы relay_init
pub const RESERVED_FIRST_BYTE: u8 = 0xEF;

// Потолок простоя сессии. Раньше здесь было 120 с: если мобильная сеть
// «съедала» TCP-соединение (типичный обрыв на LTE/переключении Wi-Fi), прокси
// узнавал об этом только через 2 минуты — всё это время Telegram показывал
// «Подключение прокси…» и сообщения не грузились. Теперь живость проверяется
// пингами и ответом на них (см. BRIDGE_PONG_TIMEOUT), поэтому общий таймаут
// можно держать коротким.
pub const BRIDGE_READ_TIMEOUT: Duration = Duration::from_secs(45);
/// Период app-level ping в активной сессии (WebSocket ping + pong).
pub const BRIDGE_PING_INTERVAL: Duration = Duration::from_secs(12);
/// Сколько ждём pong/любой ответ после нашего ping. Нет ответа — соединение
/// мертво (TCP-blackhole на мобильной сети), закрываем сразу.
pub const BRIDGE_PONG_TIMEOUT: Duration = Duration::from_secs(6);
/// Сколько ждём первый ответ от Telegram после того, как клиент отправил
/// данные. Если ответа нет — маршрут «полуживой»: WS/Cloudflare отдал 101,
/// но MTProto через него не идёт. Telegram в этом случае висит на
/// «Обновление...», поэтому сессию нужно закрыть и пометить маршрут плохим,
/// чтобы следующая попытка ушла на другой домен/маршрут.
pub const BRIDGE_FIRST_DOWNSTREAM_TIMEOUT: Duration = Duration::from_secs(15);
/// Шаг проверки «мёртвой» сессии.
pub const BRIDGE_WATCHDOG_INTERVAL: Duration = Duration::from_secs(1);
pub const WS_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
pub const WS_CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
pub const WS_BRIDGE_CHUNK_SIZE: usize = 64 * 1024;
pub const POOLED_FRAME_CAP: usize = WS_BRIDGE_CHUNK_SIZE + 32;

// proxy/pool.py::_WsPool
pub const WS_POOL_REUSE_MAX_AGE: f64 = 120.0;
pub const WS_POOL_CHECK_INTERVAL: f64 = 5.0;
pub const WS_POOL_REFILL_BACKOFF_INITIAL: f64 = 1.0;
pub const WS_POOL_REFILL_BACKOFF_MAX: f64 = 3600.0;
pub const WS_POOL_CONNECT_TIMEOUT: f64 = 8.0;
pub const WS_POOL_FRONTING_TIMEOUT: f64 = 7.0;
pub const FRONTING_SNI: &str = "sprinthost.ru";

// proxy/pool.py::_CfWorkerPool
pub const CF_WORKER_POOL_MAX_AGE: f64 = 100.0;
pub const CF_WORKER_PER_DC_LIMIT: usize = 1;

// WS пути — proxy/utils.py
pub const WS_PATH: &str = "/apiws";
pub const WS_PATH_TEST: &str = "/apiws_test";

pub const CFPROXY_CACHE_FILE_NAME: &str = "cfproxy-domains-cache.txt";
pub const CFPROXY_ACTIVE_FILE_NAME: &str = "cfproxy-active-domain.txt";
// Оригинал обновляет пул раз в час (3600с) фоновым потоком.
pub const CFPROXY_REFRESH_INTERVAL: Duration = Duration::from_secs(3600);
pub const CFPROXY_MIN_VALID_DOMAINS: usize = 3;

// Health-кулдаун доменов: после серии ошибок домен временно исключается
// из ротации, чтобы мёртвые домены не съедали время подключения.
pub const DOMAIN_FAIL_COOLDOWN_INITIAL: Duration = Duration::from_secs(30);
pub const DOMAIN_FAIL_COOLDOWN_MAX: Duration = Duration::from_secs(1800);
pub const CFPROXY_DIAL_PHASE_TIMEOUT: Duration = Duration::from_secs(3);
pub const CFPROXY_FALLBACK_PARALLEL: usize = 2;
pub const CFPROXY_429_COOLDOWN: Duration = Duration::from_secs(45);
pub const CFPROXY_429_MAX_COOLDOWN: Duration = Duration::from_secs(300);
pub const CFPROXY_GLOBAL_PARALLEL: usize = 4;

pub static RECV_BUF: AtomicI32 = AtomicI32::new(DEFAULT_RECV_BUF as i32);
pub static SEND_BUF: AtomicI32 = AtomicI32::new(DEFAULT_SEND_BUF as i32);
pub static BUFFER_SIZE: AtomicI32 = AtomicI32::new(256 * 1024);
pub static POOL_SIZE: AtomicI32 = AtomicI32::new(DEFAULT_POOL_SZ);
pub static LOG_VERBOSE: AtomicBool = AtomicBool::new(false);
// proxy/config.py::ProxyConfig — мобильные эквиваленты
// По умолчанию используем TLS (443). Раньше здесь стоял `true`, из-за чего
// ВСЕ соединения (CF-домены, воркеры, прямой WS) шли на порт 80 — на
// мобильных сетях он часто заблокирован, и в логах был сплошной
// «CF fail ...: timeout» по всем доменам сразу.
pub static DISABLE_SECURE: AtomicBool = AtomicBool::new(false);
pub static FORCE_TEST_DC: AtomicBool = AtomicBool::new(false);
pub static PROXY_PROTOCOL: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
pub struct Cfproxy429State {
    pub until: Option<Instant>,
    pub strikes: i32,
}

impl Default for Cfproxy429State {
    fn default() -> Self {
        Cfproxy429State { until: None, strikes: 0 }
    }
}

// Cloudflare proxy config
pub static CFPROXY_ENABLED: AtomicBool = AtomicBool::new(true);

pub struct CfproxyConfig {
    /// Сырая строка пользователя (для совместимости/диагностики).
    pub user_domain: String,
    /// Канонические пользовательские домены (используются как есть).
    pub user_domains: Vec<String>,
    pub domains: Vec<String>,
    pub active: String,
    pub cache_dir: String,
}

pub static CFPROXY: Lazy<RwLock<CfproxyConfig>> = Lazy::new(|| {
    RwLock::new(CfproxyConfig {
        user_domain: String::new(),
        user_domains: Vec::new(),
        domains: Vec::new(),
        active: String::new(),
        cache_dir: String::new(),
    })
});

/// Пользовательские URL со списками доменов (plain-text, домен на строку).
pub static CFPROXY_EXTRA_URLS: Lazy<RwLock<Vec<String>>> =
    Lazy::new(|| RwLock::new(Vec::new()));

/// Внешний SOCKS5/HTTP-апстрим для всех исходящих соединений
/// (например, SOCKS5-шлюз поверх Cloudflare WARP). Пусто — напрямую.
pub static UPSTREAM_PROXY_URL: Lazy<RwLock<String>> =
    Lazy::new(|| RwLock::new(String::new()));

// Обход DPI: фрагментация первого TCP-сегмента (TLS ClientHello).
pub static DPI_BYPASS_ENABLED: AtomicBool = AtomicBool::new(true);
pub static DPI_FRAG_SIZE: AtomicI32 = AtomicI32::new(1);
pub static DPI_FRAG_DELAY_MS: AtomicI32 = AtomicI32::new(25);

// proxy/config.py: cfproxy_worker_domains + fake_tls_domain
pub static CF_WORKER_DOMAINS: Lazy<RwLock<Vec<String>>> =
    Lazy::new(|| RwLock::new(Vec::new()));
pub static FAKE_TLS_DOMAIN: Lazy<RwLock<String>> =
    Lazy::new(|| RwLock::new(String::new()));

pub static CFPROXY_429: Lazy<RwLock<HashMap<String, Cfproxy429State>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Источники списка CF-доменов. Первый — оригинал Flowseal (закодированный
/// формат .com -> .co.uk), остальные — зеркала на случай блокировки
/// raw.githubusercontent.com. Пользовательские URL добавляются поверх.
pub static CFPROXY_DOMAINS_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt",
    "https://cdn.jsdelivr.net/gh/Flowseal/tg-ws-proxy@main/.github/cfproxy-domains.txt",
];

// ---------------------------------------------------------------------------
// Health-состояние доменов: эскалирующийся cooldown после ошибок подключения
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DomainFailState {
    pub until: Option<std::time::Instant>,
    pub strikes: i32,
}

impl Default for DomainFailState {
    fn default() -> Self {
        DomainFailState {
            until: None,
            strikes: 0,
        }
    }
}

pub static DOMAIN_FAIL: Lazy<RwLock<HashMap<String, DomainFailState>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

fn domain_key(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_lowercase()
}

/// Сколько ещё домен «плохой» (ZERO — можно использовать).
pub fn domain_fail_remaining(domain: &str) -> Duration {
    let key = domain_key(domain);
    if key.is_empty() {
        return Duration::ZERO;
    }
    let state = match DOMAIN_FAIL.read().get(&key).cloned() {
        Some(s) => s,
        None => return Duration::ZERO,
    };
    let until = match state.until {
        Some(u) => u,
        None => return Duration::ZERO,
    };
    let now = std::time::Instant::now();
    if until <= now {
        DOMAIN_FAIL.write().remove(&key);
        return Duration::ZERO;
    }
    until - now
}

/// Пометить домен плохим: cooldown растёт экспоненциально (30с -> ... -> 30мин).
pub fn mark_domain_fail(domain: &str) {
    let key = domain_key(domain);
    if key.is_empty() {
        return;
    }
    let mut map = DOMAIN_FAIL.write();
    let prev = map.get(&key).cloned().unwrap_or_default();
    let now = std::time::Instant::now();
    let expired = match prev.until {
        None => true,
        Some(u) => u <= now,
    };
    let mut strikes = if expired {
        // если прошлый cooldown истёк давно — начинаем с чистого листа
        if prev.strikes > 0 {
            match prev.until {
                Some(u) if now.duration_since(u) > DOMAIN_FAIL_COOLDOWN_MAX => 0,
                _ => prev.strikes,
            }
        } else {
            0
        }
    } else {
        prev.strikes
    };
    strikes += 1;
    let mut delay = DOMAIN_FAIL_COOLDOWN_INITIAL;
    for _ in 1..strikes {
        delay *= 2;
        if delay >= DOMAIN_FAIL_COOLDOWN_MAX {
            delay = DOMAIN_FAIL_COOLDOWN_MAX;
            break;
        }
    }
    map.insert(
        key,
        DomainFailState {
            until: Some(now + delay),
            strikes,
        },
    );
}

pub fn clear_domain_fail(domain: &str) {
    let key = domain_key(domain);
    if !key.is_empty() {
        DOMAIN_FAIL.write().remove(&key);
    }
}

/// Пользовательский домен: используется как есть (без декодирования и
/// без требования .co.uk). Принимает URL-мусор вида https://x.y/path:443.
pub fn canonicalize_user_domain(raw: &str) -> Option<String> {
    let mut s = raw.trim().to_lowercase();
    for p in ["https://", "http://", "wss://", "ws://"] {
        if let Some(r) = s.strip_prefix(p) {
            s = r.to_string();
        }
    }
    if let Some(idx) = s.find('/') {
        s.truncate(idx);
    }
    if let Some(idx) = s.find('?') {
        s.truncate(idx);
    }
    // порт в конце (не IPv6 — домены только)
    if let Some(idx) = s.find(':') {
        if !s[idx + 1..].is_empty() && s[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
            s.truncate(idx);
        }
    }
    let s = s.trim().trim_end_matches('.').to_string();
    if s.is_empty() || !is_valid_domain(&s) {
        return None;
    }
    Some(s)
}

/// Каноникализация записи из внешнего списка доменов.
/// Записи с суффиксом ".com" — обфусцированный встроенный формат Flowseal
/// (декодируется в ".co.uk"), остальное берётся как есть. Это позволяет
/// смешивать в одном списке и encoded-домены, и обычные (my-proxy.example.org и т.п.).
pub fn canonicalize_pool_entry(raw: &str) -> Option<String> {
    let item = raw.trim().to_lowercase();
    if item.is_empty() {
        return None;
    }
    let cand = if item.ends_with(".com") {
        crate::cfproxy::decode_cf_domain(&item)
    } else {
        item.clone()
    };
    let cand = cand.trim().trim_end_matches('.').to_string();
    if cand.is_empty() || !is_valid_domain(&cand) {
        return None;
    }
    Some(cand)
}

// MTProto proxy secret
pub static PROXY_SECRET: Lazy<RwLock<String>> =
    Lazy::new(|| RwLock::new("00000000000000000000000000000000".to_string()));

/// Нормализация секрета: принимает `dd<32hex>`, `ee<32hex><domain_hex>`,
/// голые 32 hex, лишние пробелы. Возвращает ровно 32 hex-символа в нижнем
/// регистре либо None.
///
/// Раньше невалидный секрет молча игнорировался, и прокси стартовал с
/// дефолтным `0000…`: Telegram присылал свой секрет, расшифровка не сходилась,
/// и в логах бесконечно сыпалось «bad handshake (wrong secret or proto)».
pub fn sanitize_secret(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    // Секрет — только ASCII: иначе срез по байтам ниже мог бы запаниковать.
    if !s.is_ascii() {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    // Полный секрет из ссылки Telegram: dd/ee + сам секрет (+ домен для ee).
    let body = if lower.len() > 32 && (lower.starts_with("dd") || lower.starts_with("ee")) {
        &lower[2..]
    } else {
        &lower[..]
    };
    if body.len() < 32 {
        return None;
    }
    let secret = &body[..32];
    if secret.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(secret.to_string())
    } else {
        None
    }
}

/// Недавние секреты (например, предыдущий секрет, пока в Telegram осталась
/// старая ссылка). Прокси принимает их наравне с активным — это убирает
/// «bad handshake» после смены секрета без переприменения ссылки.
pub static SECRET_HISTORY: Lazy<RwLock<Vec<String>>> = Lazy::new(|| RwLock::new(Vec::new()));

/// Все секреты, которые принимает прокси: активный + история.
/// Возвращает (секрет, байты).
pub fn secret_candidates() -> Vec<(String, Vec<u8>)> {
    let active = PROXY_SECRET.read().clone();
    let mut list: Vec<String> = vec![active.clone()];
    for s in SECRET_HISTORY.read().iter() {
        if !list.contains(s) {
            list.push(s.clone());
        }
    }
    let mut out = Vec::new();
    for s in list {
        if let Some(normalized) = sanitize_secret(&s) {
            if let Ok(bytes) = hex::decode(&normalized) {
                if bytes.len() == 16 {
                    out.push((normalized, bytes));
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Circuit breaker для маршрута Cloudflare
//
// Если все CF-домены подряд отваливаются по таймауту (типичная картина при
// блокировке Cloudflare у провайдера), нет смысла на каждом соединении ждать
// по 5 секунд на домен: маршрут временно отключается целиком.
// ---------------------------------------------------------------------------

pub static CF_CONSECUTIVE_FAILS: AtomicU32 = AtomicU32::new(0);
pub static CF_CIRCUIT_OPEN_UNTIL: AtomicU64 = AtomicU64::new(0);
pub const CF_CIRCUIT_FAIL_THRESHOLD: u32 = 3;
pub const CF_CIRCUIT_OPEN_SECS: u64 = 45;

pub fn cf_circuit_open() -> bool {
    let until = CF_CIRCUIT_OPEN_UNTIL.load(Ordering::Relaxed);
    until > 0 && (now_unix() as u64) < until
}

pub fn cf_circuit_note_success() {
    CF_CONSECUTIVE_FAILS.store(0, Ordering::Relaxed);
    CF_CIRCUIT_OPEN_UNTIL.store(0, Ordering::Relaxed);
}

pub fn cf_circuit_note_failure() {
    let n = CF_CONSECUTIVE_FAILS.fetch_add(1, Ordering::Relaxed) + 1;
    if n >= CF_CIRCUIT_FAIL_THRESHOLD {
        let was_open = cf_circuit_open();
        CF_CIRCUIT_OPEN_UNTIL
            .store(now_unix() as u64 + CF_CIRCUIT_OPEN_SECS, Ordering::Relaxed);
        CF_CONSECUTIVE_FAILS.store(0, Ordering::Relaxed);
        if !was_open {
            log_warn(&format!(
                " CF: маршрут Cloudflare временно отключён на {}с ({} неудач подряд)",
                CF_CIRCUIT_OPEN_SECS, n
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// RTT / здоровье маршрутов
// ---------------------------------------------------------------------------

/// Записать измеренный RTT (мс): мгновенное значение + сглаженное среднее.
/// Сглаживание (EWMA 0.3) — чтобы «прыгающий» пинг в UI не мигал с 40 на 4000.
pub fn record_ping_rtt(ms: u64) {
    if ms == 0 || ms > 120_000 {
        return;
    }
    STATS.ping_ms.store(ms as i64, Ordering::Relaxed);
    let prev = STATS.ping_avg_ms.load(Ordering::Relaxed);
    let next = if prev <= 0 {
        ms as i64
    } else {
        (prev * 7 + ms as i64 * 3) / 10
    };
    STATS.ping_avg_ms.store(next, Ordering::Relaxed);
}

/// Маршрут до Telegram. Код идёт в статистику (`route=`), чтобы UI показывал,
/// через что сейчас идёт трафик.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    Direct = 1,
    Worker = 2,
    CfPool = 3,
    Tcp = 4,
}

impl RouteKind {
    pub fn code(self) -> i64 {
        self as i64
    }

    pub fn label(self) -> &'static str {
        match self {
            RouteKind::Direct => "direct-ws",
            RouteKind::Worker => "worker",
            RouteKind::CfPool => "cf-pool",
            RouteKind::Tcp => "tcp",
        }
    }

    pub fn from_code(v: i64) -> Option<RouteKind> {
        match v {
            1 => Some(RouteKind::Direct),
            2 => Some(RouteKind::Worker),
            3 => Some(RouteKind::CfPool),
            4 => Some(RouteKind::Tcp),
            _ => None,
        }
    }
}

/// «Липкий» лучший маршрут для DC: если прямой WS недавно работал, незачем
/// каждый раз сначала тратить время на Cloudflare (и наоборот).
#[derive(Debug, Clone, Copy)]
pub struct RouteHealth {
    pub best: RouteKind,
    /// when_monotonic последнего успеха
    pub best_at: f64,
    /// когда маршрут был помечен плохим (0 — не был)
    pub bad_at: f64,
}

pub static ROUTE_HEALTH: Lazy<RwLock<HashMap<i32, RouteHealth>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Сколько «липкий» маршрут считается свежим.
pub const ROUTE_STICKY_TTL: f64 = 900.0;
/// Сколько маршрут считается плохим после мёртвой сессии.
pub const ROUTE_BAD_TTL: f64 = 120.0;

pub fn route_mark_good(dc: i32, route: RouteKind) {
    let mut map = ROUTE_HEALTH.write();
    let entry = map.entry(dc).or_insert(RouteHealth {
        best: route,
        best_at: 0.0,
        bad_at: 0.0,
    });
    entry.best = route;
    entry.best_at = now_monotonic();
    entry.bad_at = 0.0;
    STATS.last_route.store(route.code(), Ordering::Relaxed);
}

pub fn route_mark_bad(dc: i32, route: RouteKind) {
    let mut map = ROUTE_HEALTH.write();
    let entry = map.entry(dc).or_insert(RouteHealth {
        best: route,
        best_at: 0.0,
        bad_at: 0.0,
    });
    entry.bad_at = now_monotonic();
    entry.best_at = 0.0;
}

/// Свежий рабочий маршрут для DC (или None, если истории нет / она устарела).
pub fn route_preferred(dc: i32) -> Option<RouteKind> {
    let map = ROUTE_HEALTH.read();
    let h = map.get(&dc)?;
    let now = now_monotonic();
    if h.best_at > 0.0 && now - h.best_at <= ROUTE_STICKY_TTL {
        Some(h.best)
    } else {
        None
    }
}

/// Маршрут недавно «умирал» (нет pong / нет downstream)?
pub fn route_recently_bad(dc: i32, route: RouteKind) -> bool {
    let map = ROUTE_HEALTH.read();
    match map.get(&dc) {
        Some(h) => h.bad_at > 0.0 && now_monotonic() - h.bad_at <= ROUTE_BAD_TTL && h.best != route,
        None => false,
    }
}

/// Сколько раз в текущем окне маршрут Cloudflare был пропущен (для логов).
pub static CF_SKIPPED_LOGGED: AtomicBool = AtomicBool::new(false);

/// Дедупликация INFO-логов, которые иначе повторяются на каждом соединении.
pub fn log_once_per(key: &str, window_secs: u64) -> bool {
    use std::collections::HashMap;
    static SEEN: Lazy<RwLock<HashMap<String, i64>>> = Lazy::new(|| RwLock::new(HashMap::new()));
    let now = now_unix();
    let mut map = SEEN.write();
    let last = map.get(key).copied().unwrap_or(0);
    if now - last >= window_secs as i64 {
        map.insert(key.to_string(), now);
        true
    } else {
        false
    }
}

/// Не чаще одного сообщения в `window_secs`; возвращает число подавленных
/// повторов (0 — если это первое сообщение в окне).
static BAD_HANDSHAKE_LAST_LOG: AtomicU64 = AtomicU64::new(0);
static BAD_HANDSHAKE_SUPPRESSED: AtomicU64 = AtomicU64::new(0);

pub fn bad_handshake_log_gate(window_secs: u64) -> Option<u64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last = BAD_HANDSHAKE_LAST_LOG.load(Ordering::Relaxed);
    if now.saturating_sub(last) >= window_secs {
        BAD_HANDSHAKE_LAST_LOG.store(now, Ordering::Relaxed);
        Some(BAD_HANDSHAKE_SUPPRESSED.swap(0, Ordering::Relaxed))
    } else {
        BAD_HANDSHAKE_SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        None
    }
}

/// Сколько всего было «плохих» рукопожатий (для диагностики/UI).
pub static BAD_HANDSHAKES_TOTAL: AtomicU64 = AtomicU64::new(0);

// proxy/config.py::_CFPROXY_ENC — полный список из 20 доменов оригинала.
pub static CFPROXY_ENC: &[&str] = &[
    "virkgj.com",
    "vmmzovy.com",
    "mkuosckvso.com",
    "zaewayzmplad.com",
    "twdmbzcm.com",
    "awzwsldi.com",
    "clngqrflngqin.com",
    "tjacxbqtj.com",
    "bxaxtxmrw.com",
    "dmohrsgmohcrwb.com",
    "vwbmtmoi.com",
    "khgrre.com",
    "ulihssf.com",
    "tmhqsdqmfpmk.com",
    "xwuwoqbm.com",
    "orgcnunpj.com",
    "zhkuldz.com",
    "zypoljnslxa.com",
    "efabnxaowuzs.com",
    "zaftuzsftqdq.com",
];

// DC default IPs — proxy/utils.py::DC_DEFAULT_IPS
pub static DC_DEFAULT_IPS: Lazy<HashMap<i32, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert(1, "149.154.175.50");
    m.insert(2, "149.154.167.51");
    m.insert(3, "149.154.175.100");
    m.insert(4, "149.154.167.91");
    m.insert(5, "149.154.171.5");
    m.insert(203, "91.105.192.100");
    m
});

// proxy/utils.py::DC_TEST_IPS
pub static DC_TEST_IPS: Lazy<HashMap<i32, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert(1, "149.154.175.10");
    m.insert(2, "149.154.167.40");
    m.insert(3, "149.154.175.117");
    m
});

// Telegram protocols & DC mapping
pub fn valid_proto(p: u32) -> bool {
    matches!(p, 0xEFEFEFEF | 0xEEEEEEEE | 0xDDDDDDDD)
}

pub static DC_OVERRIDES: Lazy<HashMap<i32, i32>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert(203, 2);
    m
});

// Ключ состояния DC: (dc, is_media, is_test) — аналог строки
// f'{dc}{"t" if is_test else ""}{"m" if is_media else ""}' из оригинала.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct DcKey {
    pub dc: i32,
    pub is_media: i32,
    pub is_test: i32,
}

impl DcKey {
    pub fn new(dc: i32, is_media: bool, is_test: bool) -> Self {
        DcKey {
            dc,
            is_media: if is_media { 1 } else { 0 },
            is_test: if is_test { 1 } else { 0 },
        }
    }

    pub fn as_str_key(&self) -> String {
        format!(
            "{}{}{}",
            self.dc,
            if self.is_test != 0 { "t" } else { "" },
            if self.is_media != 0 { "m" } else { "" }
        )
    }
}

// Global state — proxy/tg_ws_proxy.py: ws_blacklist / dc_fail_until / ip_fail_until
pub static DC_OPT: Lazy<RwLock<HashMap<i32, String>>> = Lazy::new(|| RwLock::new(HashMap::new()));
pub static WS_BLACKLIST: Lazy<RwLock<HashMap<DcKey, bool>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));
pub static DC_FAIL_UNTIL: Lazy<RwLock<HashMap<DcKey, f64>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));
pub static IP_FAIL_UNTIL: Lazy<RwLock<HashMap<String, f64>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

pub static ZERO64: [u8; 64] = [0u8; 64];

// ---------------------------------------------------------------------------
// Domain validation — proxy/config.py::_is_valid_domain / _normalize_domain_pool
// ---------------------------------------------------------------------------

pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|ch| ch.is_alphanumeric() || ch == '-') {
            return false;
        }
    }
    let tld = labels[labels.len() - 1];
    if tld.len() < 2 || !tld.chars().any(|ch| ch.is_alphabetic()) {
        return false;
    }
    true
}

pub fn normalize_domain_pool(domains: &[String]) -> Vec<String> {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for d in domains {
        let item = d.trim().to_lowercase();
        if !is_valid_domain(&item) {
            continue;
        }
        if seen.contains(&item) {
            continue;
        }
        seen.insert(item.clone());
        out.push(item);
    }
    out
}

/// proxy/config.py::coerce_domain_list — строка или список через , ; пробелы.
pub fn coerce_domain_list_str(value: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for item in value.replace(',', " ").replace(';', " ").split_whitespace() {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let key = item.to_lowercase();
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);
        result.push(item.to_string());
    }
    result
}

// ---------------------------------------------------------------------------
// Reserved relay_init checks — proxy/utils.py
// ---------------------------------------------------------------------------

pub fn is_reserved_start(s: &[u8]) -> bool {
    if s.len() < 4 {
        return false;
    }
    let s4 = &s[..4];
    s4 == b"HEAD"
        || s4 == b"POST"
        || s4 == b"GET "
        || s4 == [0xee, 0xee, 0xee, 0xee]
        || s4 == [0xdd, 0xdd, 0xdd, 0xdd]
        || s4 == [0x16, 0x03, 0x01, 0x02]
}

// ---------------------------------------------------------------------------
// Stats — proxy/stats.py
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct Stats {
    pub connections_total: AtomicI64,
    pub connections_active: AtomicI64,
    pub connections_ws: AtomicI64,
    pub connections_tcp_fallback: AtomicI64,
    pub connections_cfproxy: AtomicI64,
    pub connections_fronting: AtomicI64,
    pub connections_bad: AtomicI64,
    pub connections_masked: AtomicI64,
    pub connections_http_reject: AtomicI64,
    pub connections_passthrough: AtomicI64,
    pub ws_errors: AtomicI64,
    pub bytes_up: AtomicI64,
    pub bytes_down: AtomicI64,
    pub pool_hits: AtomicI64,
    pub pool_misses: AtomicI64,
    pub cf_pool_hits: AtomicI64,
    pub cf_pool_misses: AtomicI64,
    /// Последний измеренный RTT пинга через активный WS (мс).
    pub ping_ms: AtomicI64,
    /// Скользящее среднее RTT (мс) — сглаживает «скачущий» пинг.
    pub ping_avg_ms: AtomicI64,
    /// Сколько раз сессия закрывалась по мёртвому маршруту (нет pong/данных).
    pub dead_sessions: AtomicI64,
    /// Код текущего маршрута: 0 неизвестен, 1 прямой WS, 2 worker, 3 CF, 4 TCP.
    pub last_route: AtomicI64,
}

pub static STATS: Lazy<Stats> = Lazy::new(Stats::default);

impl Stats {
    pub fn summary(&self) -> String {
        let ph = self.pool_hits.load(Ordering::Relaxed);
        let pm = self.pool_misses.load(Ordering::Relaxed);
        let pool_total = ph + pm;
        let pool_s = if pool_total > 0 {
            format!("{}/{}", ph, pool_total)
        } else {
            "n/a".to_string()
        };
        let cph = self.cf_pool_hits.load(Ordering::Relaxed);
        let cpm = self.cf_pool_misses.load(Ordering::Relaxed);
        let cf_total = cph + cpm;
        let cf_pool_s = if cf_total > 0 {
            format!("{}/{}", cph, cf_total)
        } else {
            "n/a".to_string()
        };
        format!(
            "total={} active={} ws={} tcp_fb={} cf={} front={} bad={} masked={} err={} pool={} cf_pool={} up={} down={}",
            self.connections_total.load(Ordering::Relaxed),
            self.connections_active.load(Ordering::Relaxed),
            self.connections_ws.load(Ordering::Relaxed),
            self.connections_tcp_fallback.load(Ordering::Relaxed),
            self.connections_cfproxy.load(Ordering::Relaxed),
            self.connections_fronting.load(Ordering::Relaxed),
            self.connections_bad.load(Ordering::Relaxed),
            self.connections_masked.load(Ordering::Relaxed),
            self.ws_errors.load(Ordering::Relaxed),
            pool_s,
            cf_pool_s,
            human_bytes(self.bytes_up.load(Ordering::Relaxed)),
            human_bytes(self.bytes_down.load(Ordering::Relaxed)),
        ) + &format!(
            " ping={} ping_avg={} dead={} route={}",
            self.ping_ms.load(Ordering::Relaxed),
            self.ping_avg_ms.load(Ordering::Relaxed),
            self.dead_sessions.load(Ordering::Relaxed),
            self.last_route.load(Ordering::Relaxed),
        )
    }

    pub fn summary_ru(&self) -> String {
        let mut parts = vec![format!("акт:{}", self.connections_active.load(Ordering::Relaxed))];
        let ws = self.connections_ws.load(Ordering::Relaxed);
        if ws > 0 {
            parts.push(format!("ws:{}", ws));
        }
        let cf = self.connections_cfproxy.load(Ordering::Relaxed);
        if cf > 0 {
            parts.push(format!("cf:{}", cf));
        }
        let tcp = self.connections_tcp_fallback.load(Ordering::Relaxed);
        if tcp > 0 {
            parts.push(format!("tcp:{}", tcp));
        }
        let err = self.ws_errors.load(Ordering::Relaxed);
        if err > 0 {
            parts.push(format!("ош:{}", err));
        }
        parts.push(format!(
            "↑{} ↓{}",
            human_bytes(self.bytes_up.load(Ordering::Relaxed)),
            human_bytes(self.bytes_down.load(Ordering::Relaxed))
        ));
        parts.join(" | ")
    }

    pub fn reset(&self) {
        self.connections_total.store(0, Ordering::Relaxed);
        self.connections_active.store(0, Ordering::Relaxed);
        self.connections_ws.store(0, Ordering::Relaxed);
        self.connections_tcp_fallback.store(0, Ordering::Relaxed);
        self.connections_cfproxy.store(0, Ordering::Relaxed);
        self.connections_fronting.store(0, Ordering::Relaxed);
        self.connections_bad.store(0, Ordering::Relaxed);
        self.connections_masked.store(0, Ordering::Relaxed);
        self.connections_http_reject.store(0, Ordering::Relaxed);
        self.connections_passthrough.store(0, Ordering::Relaxed);
        self.ws_errors.store(0, Ordering::Relaxed);
        self.bytes_up.store(0, Ordering::Relaxed);
        self.bytes_down.store(0, Ordering::Relaxed);
        self.pool_hits.store(0, Ordering::Relaxed);
        self.pool_misses.store(0, Ordering::Relaxed);
        self.cf_pool_hits.store(0, Ordering::Relaxed);
        self.cf_pool_misses.store(0, Ordering::Relaxed);
    }
}

pub fn human_bytes(n: i64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut f = n as f64;
    for (i, u) in units.iter().enumerate() {
        if f.abs() < 1024.0 || i == units.len() - 1 {
            return format!("{:.1}{}", f, u);
        }
        f /= 1024.0;
    }
    format!("{:.1}TB", f)
}

// ---------------------------------------------------------------------------
// Logger (Android log + stderr, 1-в-1 префиксы)
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
fn android_log_line(line: &str) {
    use std::ffi::CString;
    unsafe extern "C" {
        fn __android_log_print(prio: i32, tag: *const i8, fmt: *const i8, ...) -> i32;
    }
    const ANDROID_LOG_INFO: i32 = 4;
    if let (Ok(tag), Ok(fmt), Ok(msg)) =
        (CString::new("TgWsProxy"), CString::new("%s"), CString::new(line))
    {
        unsafe {
            __android_log_print(
                ANDROID_LOG_INFO,
                tag.as_ptr() as *const i8,
                fmt.as_ptr() as *const i8,
                msg.as_ptr() as *const i8,
            );
        }
    }
}

#[cfg(not(target_os = "android"))]
fn android_log_line(_line: &str) {}

// Цензура доменов в логах — аналог DomainCensorFilter из proxy/utils.py:
// telegram.org и *.telegram.org не маскируем, остальное частично маскируем.
fn censor_domains(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let bytes = msg.as_bytes();
    let mut i = 0;
    while i < msg.len() {
        let start = i;
        while i < msg.len()
            && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'-' || bytes[i] == b'.')
        {
            i += 1;
        }
        if start == i {
            let ch = msg[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        let token = &msg[start..i];
        if token.contains('.') && token.len() > 4 && is_likely_domain(token) {
            let lower = token.to_lowercase();
            let trimmed = lower.trim_end_matches('.');
            if trimmed == "telegram.org"
                || trimmed.ends_with(".telegram.org")
                || trimmed.ends_with(".log")
            {
                out.push_str(token);
            } else {
                out.push_str(&mask_domain(token));
            }
        } else {
            out.push_str(token);
        }
    }
    out
}

fn is_likely_domain(token: &str) -> bool {
    let t = token.trim_end_matches('.');
    let parts: Vec<&str> = t.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let tld = parts[parts.len() - 1];
    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty()
            && p.len() <= 63
            && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

fn mask_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 {
        return domain.to_string();
    }
    parts
        .iter()
        .enumerate()
        .map(|(idx, p)| {
            if idx == parts.len() - 1 {
                p.to_string()
            } else {
                let keep = p.len() / 2;
                format!("{}{}", &p[..keep], "*".repeat(p.len() - keep))
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn emit(prefix: &str, msg: &str) {
    let line = format!("{}{}", prefix, censor_domains(msg));
    eprintln!("{}", line);
    android_log_line(&line);
}

pub fn log_info(msg: &str) {
    emit("", msg);
}
pub fn log_warn(msg: &str) {
    emit("[WARN] ", msg);
}
pub fn log_error(msg: &str) {
    emit("[ERROR] ", msg);
}
pub fn log_debug(msg: &str) {
    if LOG_VERBOSE.load(Ordering::Relaxed) {
        emit("[DEBUG] ", msg);
    }
}

#[macro_export]
macro_rules! linfo  { ($($a:tt)*) => { $crate::config::log_info(&format!($($a)*)) }; }
#[macro_export]
macro_rules! lwarn  { ($($a:tt)*) => { $crate::config::log_warn(&format!($($a)*)) }; }
#[macro_export]
macro_rules! lerror { ($($a:tt)*) => { $crate::config::log_error(&format!($($a)*)) }; }
#[macro_export]
macro_rules! ldebug { ($($a:tt)*) => { $crate::config::log_debug(&format!($($a)*)) }; }

pub fn init_logging(verbose: bool) {
    LOG_VERBOSE.store(verbose, Ordering::Relaxed);
}

pub fn now_unix_f64() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn now_monotonic() -> f64 {
    use std::time::Instant;
    static START: Lazy<Instant> = Lazy::new(Instant::now);
    START.elapsed().as_secs_f64()
}

#[cfg(test)]
mod secret_tests {
    use super::*;

    #[test]
    fn sanitize_accepts_plain_and_link_forms() {
        let hex = "0123456789abcdef0123456789abcdef";
        assert_eq!(sanitize_secret(hex).unwrap(), hex);
        // полный секрет из ссылки Telegram
        assert_eq!(sanitize_secret(&format!("dd{}", hex)).unwrap(), hex);
        // ee-секрет содержит домен после самого секрета
        assert_eq!(
            sanitize_secret(&format!("ee{}6b77732e6d65", hex)).unwrap(),
            hex
        );
        // верхний регистр и пробелы нормализуются
        assert_eq!(
            sanitize_secret(&format!("  {}  ", hex.to_uppercase())).unwrap(),
            hex
        );
    }

    #[test]
    fn sanitize_rejects_garbage() {
        assert!(sanitize_secret("").is_none());
        assert!(sanitize_secret("0000").is_none());
        assert!(sanitize_secret("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_none());
        // 32 символа, но не hex
        assert!(sanitize_secret("0123456789abcdef0123456789abcdeg").is_none());
        // не-ASCII (срез по байтам не должен паниковать)
        assert!(sanitize_secret("секрет-секрет-секрет-секрет-секр").is_none());
    }

    #[test]
    fn bad_handshake_log_is_rate_limited() {
        // окно 0 секунд — каждое сообщение считается «первым в окне»
        assert!(bad_handshake_log_gate(0).is_some());
        // окно 60 секунд — повтор сразу после первого подавляется
        assert!(bad_handshake_log_gate(60).is_none());
    }

    #[test]
    fn route_health_prefers_last_good() {
        let dc = 991;
        assert_eq!(route_preferred(dc), None);
        route_mark_good(dc, RouteKind::Worker);
        assert_eq!(route_preferred(dc), Some(RouteKind::Worker));
        route_mark_good(dc, RouteKind::Direct);
        assert_eq!(route_preferred(dc), Some(RouteKind::Direct));
        route_mark_bad(dc, RouteKind::Direct);
        assert_eq!(route_preferred(dc), None);
        assert!(route_recently_bad(dc, RouteKind::Worker));
    }

    #[test]
    fn ping_rtt_is_smoothed() {
        let before = STATS.ping_avg_ms.load(Ordering::Relaxed);
        record_ping_rtt(100);
        let first = STATS.ping_avg_ms.load(Ordering::Relaxed);
        record_ping_rtt(1000);
        let second = STATS.ping_avg_ms.load(Ordering::Relaxed);
        // Одиночный выброс не должен утащить среднее сразу к 1000 мс.
        assert!(second > first, "avg must grow");
        assert!(second < 900, "avg must stay smoothed: {}", second);
        STATS.ping_avg_ms.store(before, Ordering::Relaxed);
    }
}
