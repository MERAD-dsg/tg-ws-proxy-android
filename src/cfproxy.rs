use crate::config::*;
use crate::ws::{is_http_status_error, ws_connect_once, RawWebSocket, WsError};
use crate::{ldebug, lerror, linfo, lwarn};
use serde::Deserialize;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

use once_cell::sync::Lazy;
static CFPROXY_SEM: Lazy<Semaphore> = Lazy::new(|| Semaphore::new(CFPROXY_GLOBAL_PARALLEL));

// ---------------------------------------------------------------------------
// Domain decoding
// ---------------------------------------------------------------------------

pub fn decode_cf_domain(s: &str) -> String {
    if !s.ends_with(".com") {
        return s.to_string();
    }
    let suffix = ".co.uk";
    let p = &s[..s.len() - 4];
    let mut n = 0i32;
    for c in p.chars() {
        if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
            n += 1;
        }
    }
    let mut result: Vec<u8> = Vec::new();
    for &c in p.as_bytes() {
        if c >= b'a' && c <= b'z' {
            let v = (((c - b'a') as i32 - n % 26 + 26) % 26) as u8 + b'a';
            result.push(v);
        } else if c >= b'A' && c <= b'Z' {
            let v = (((c - b'A') as i32 - n % 26 + 26) % 26) as u8 + b'A';
            result.push(v);
        } else {
            result.push(c);
        }
    }
    let mut out = String::from_utf8_lossy(&result).to_string();
    out.push_str(suffix);
    out
}

pub fn normalize_cf_domain(s: &str) -> String {
    let mut decoded = decode_cf_domain(s.trim()).trim().to_lowercase();
    while decoded.ends_with('.') {
        decoded.pop();
    }
    if decoded.is_empty() || !decoded.ends_with(".co.uk") {
        return String::new();
    }
    decoded
}

pub fn default_cfproxy_domains() -> Vec<String> {
    let mut domains = Vec::with_capacity(CFPROXY_ENC.len());
    for enc in CFPROXY_ENC {
        let d = normalize_cf_domain(enc);
        if !d.is_empty() {
            domains.push(d);
        }
    }
    domains
}

pub fn merge_cfproxy_domains(lists: &[Vec<String>]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut merged = Vec::new();
    for list in lists {
        for raw in list {
            // Записи из внешних списков каноникализируем: encoded (.com)
            // декодируется, обычные домены (my-proxy.example.org и т.п.) берутся
            // как есть.
            let d = match crate::config::canonicalize_pool_entry(raw) {
                Some(d) => d,
                None => continue,
            };
            if seen.contains(&d) {
                continue;
            }
            seen.insert(d.clone());
            merged.push(d);
        }
    }
    merged
}

/// Пользовательские домены — строго как есть (без decode).
pub fn merge_user_domains(lists: &[Vec<String>]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut merged = Vec::new();
    for list in lists {
        for raw in list {
            let d = match crate::config::canonicalize_user_domain(raw) {
                Some(d) => d,
                None => continue,
            };
            if seen.contains(&d) {
                continue;
            }
            seen.insert(d.clone());
            merged.push(d);
        }
    }
    merged
}

// ---------------------------------------------------------------------------
// 429 cooldown logic
// ---------------------------------------------------------------------------

pub fn clear_cfproxy_429_cooldowns() {
    CFPROXY_429.write().clear();
}

fn cooldown_key(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_lowercase()
}

pub fn clear_cfproxy_429_cooldown(domain: &str) {
    let d = cooldown_key(domain);
    if d.is_empty() {
        return;
    }
    CFPROXY_429.write().remove(&d);
}

pub fn retry_after_delay(err: &WsError) -> Duration {
    let h = match err.handshake() {
        Some(h) => h,
        None => return Duration::ZERO,
    };
    let retry_after = h.headers.get("retry-after").map(|s| s.trim()).unwrap_or("");
    if retry_after.is_empty() {
        return Duration::ZERO;
    }
    if let Ok(seconds) = retry_after.parse::<i64>() {
        if seconds > 0 {
            return Duration::from_secs(seconds as u64);
        }
    }
    // http date parse (best-effort): пропускаем, как маловероятный кейс
    Duration::ZERO
}

pub fn next_cfproxy_429_cooldown_delay(prev: &Cfproxy429State, retry_after: Duration) -> Duration {
    if retry_after > Duration::ZERO {
        if retry_after > CFPROXY_429_MAX_COOLDOWN {
            return CFPROXY_429_MAX_COOLDOWN;
        }
        return retry_after;
    }
    let mut strikes = prev.strikes;
    let expired = match prev.until {
        None => true,
        Some(u) => u.elapsed() > CFPROXY_429_MAX_COOLDOWN,
    };
    if expired {
        strikes = 0;
    }
    let mut delay = CFPROXY_429_COOLDOWN;
    for _ in 0..strikes {
        delay *= 2;
        if delay >= CFPROXY_429_MAX_COOLDOWN {
            return CFPROXY_429_MAX_COOLDOWN;
        }
    }
    if delay > CFPROXY_429_MAX_COOLDOWN {
        return CFPROXY_429_MAX_COOLDOWN;
    }
    delay
}

pub fn mark_cfproxy_429_cooldown(domain: &str, err: &WsError) {
    let d = cooldown_key(domain);
    if d.is_empty() {
        return;
    }
    let retry_after = retry_after_delay(err);
    let mut map = CFPROXY_429.write();
    let prev = map.get(&d).cloned().unwrap_or_default();
    let delay = next_cfproxy_429_cooldown_delay(&prev, retry_after);
    let mut strikes = prev.strikes + 1;
    let expired = match prev.until {
        None => true,
        Some(u) => u.elapsed() > CFPROXY_429_MAX_COOLDOWN,
    };
    if expired {
        strikes = 1;
    }
    map.insert(
        d.clone(),
        Cfproxy429State {
            until: Some(Instant::now() + delay),
            strikes,
        },
    );
    drop(map);
    ldebug!(" CF cooldown {}: {:.0}s after 429", d, delay.as_secs_f64().ceil());
}

pub fn cfproxy_429_cooldown_remaining(domain: &str) -> Duration {
    let d = cooldown_key(domain);
    if d.is_empty() {
        return Duration::ZERO;
    }
    let map = CFPROXY_429.read();
    let state = match map.get(&d) {
        Some(s) => s.clone(),
        None => return Duration::ZERO,
    };
    drop(map);
    let until = match state.until {
        Some(u) => u,
        None => return Duration::ZERO,
    };
    let now = Instant::now();
    if until <= now {
        CFPROXY_429.write().remove(&d);
        return Duration::ZERO;
    }
    until - now
}

pub async fn acquire_cfproxy_attempt_slot() -> Option<tokio::sync::SemaphorePermit<'static>> {
    CFPROXY_SEM.acquire().await.ok()
}

// ---------------------------------------------------------------------------
// Cache files
// ---------------------------------------------------------------------------

fn cfproxy_cache_path() -> Option<PathBuf> {
    let dir = CFPROXY.read().cache_dir.trim().to_string();
    if dir.is_empty() {
        return None;
    }
    Some(PathBuf::from(dir).join(CFPROXY_CACHE_FILE_NAME))
}

// Активный домен больше не сохраняется в отдельный файл. Балансер работает в памяти.

fn load_cfproxy_domains_from_cache() -> Vec<String> {
    let path = match cfproxy_cache_path() {
        Some(p) => p,
        None => return Vec::new(),
    };
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let list: Vec<String> = data.split('\n').map(|s| s.to_string()).collect();
    merge_cfproxy_domains(&[list])
}



fn save_cfproxy_domains_to_cache(domains: &[String]) {
    let path = match cfproxy_cache_path() {
        Some(p) => p,
        None => return,
    };
    if domains.is_empty() {
        return;
    }
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            ldebug!(" CF: кеш создать не удалось: {}", e);
            return;
        }
    }
    let data = domains.join("\n");
    if let Err(e) = std::fs::write(&path, data) {
        ldebug!(" CF: кеш сохранить не удалось: {}", e);
    }
}



fn should_refresh_cfproxy_domains() -> bool {
    let path = match cfproxy_cache_path() {
        Some(p) => p,
        None => return true,
    };
    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(_) => return true,
    };
    let modified = match meta.modified() {
        Ok(t) => t,
        Err(_) => return true,
    };
    match modified.elapsed() {
        Ok(elapsed) => elapsed >= CFPROXY_REFRESH_INTERVAL,
        Err(_) => true,
    }
}



pub fn init_cfproxy_domains() {
    let defaults = default_cfproxy_domains();
    let cached = load_cfproxy_domains_from_cache();
    let user = CFPROXY.read().user_domains.clone();

    // Приоритет: пользовательские домены (как есть) -> кеш -> встроенный пул.
    // Всё вместе: свои домены работают первыми, авто-пул — как запасной.
    let mut merged = Vec::new();
    if !user.is_empty() {
        merged.extend(user.iter().cloned());
    }
    merged.extend(cached.iter().cloned());
    merged.extend(defaults.iter().cloned());
    merged = {
        let mut seen = std::collections::HashSet::new();
        merged
            .into_iter()
            .filter(|d| seen.insert(d.clone()))
            .collect()
    };

    let n_user = user.len();
    let n_total = merged.len();
    {
        let mut cfg = CFPROXY.write();
        cfg.domains = merged.clone();
    }
    crate::balancer::BALANCER
        .write()
        .update_domains_list_with_priority(n_user, &merged);
    if n_user > 0 {
        linfo!(
            " CF: пользовательские домены ({}) + авто-пул, всего {}",
            n_user,
            n_total
        );
    }
}

pub fn start_cfproxy_refresh() {
    // Одна фоновая петля на процесс: сначала пробуем обновить сразу
    // (до 3 попыток), затем раз в час.
    static REFRESH_STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if REFRESH_STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    tokio::spawn(async move {
        if should_refresh_cfproxy_domains() {
            for _ in 0..3 {
                if try_refresh_cfproxy_domains().await {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
        loop {
            tokio::time::sleep(CFPROXY_REFRESH_INTERVAL).await;
            try_refresh_cfproxy_domains().await;
        }
    });
}

/// Все источники списков доменов: пользовательские URL, затем встроенные.
fn domain_list_sources() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for u in CFPROXY_EXTRA_URLS.read().iter() {
        let u = u.trim().to_string();
        if u.starts_with("http://") || u.starts_with("https://") {
            out.push(u);
        }
    }
    for u in CFPROXY_DOMAINS_URLS {
        out.push(u.to_string());
    }
    out
}

async fn fetch_domain_list_source(client: &reqwest::Client, url: &str) -> Option<Vec<String>> {
    // Cache-buster как в оригинале ("?" + 7 случайных букв), UA tg-ws-proxy.
    let nonce: String = {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..7)
            .map(|_| rng.gen_range(b'a'..=b'z') as char)
            .collect()
    };
    let full = format!("{}{}{}", url, if url.contains('?') { "&" } else { "?" }, nonce);
    let resp = match client
        .get(&full)
        .header("User-Agent", "tg-ws-proxy")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            ldebug!(" CF: источник {} недоступен: {}", url, e);
            return None;
        }
    };
    if resp.status().as_u16() != 200 {
        ldebug!(" CF: источник {} вернул {}", url, resp.status().as_u16());
        return None;
    }
    let body = match resp.text().await {
        Ok(b) => b,
        Err(e) => {
            ldebug!(" CF: источник {} не прочитался: {}", url, e);
            return None;
        }
    };
    let mut lines = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        lines.push(line.to_string());
    }
    if lines.is_empty() {
        None
    } else {
        Some(lines)
    }
}

pub async fn try_refresh_cfproxy_domains() -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    let mut all_raw: Vec<String> = Vec::new();
    let mut sources_used = 0;
    for url in domain_list_sources() {
        if let Some(lines) = fetch_domain_list_source(&client, &url).await {
            sources_used += 1;
            all_raw.extend(lines);
        }
    }
    if all_raw.is_empty() {
        ldebug!(" CF: обновить список доменов не удалось (все источники недоступны)");
        return false;
    }

    let pool = merge_cfproxy_domains(&[all_raw.clone()]);
    if pool.len() < CFPROXY_MIN_VALID_DOMAINS {
        lwarn!(
            " CF: игнорирую список доменов (total={}, valid={}, need>={}); остаюсь на текущем пуле",
            all_raw.len(),
            pool.len(),
            CFPROXY_MIN_VALID_DOMAINS
        );
        return false;
    }

    // Склеиваем: пользовательские -> свежий пул -> кеш -> встроенный.
    let user = CFPROXY.read().user_domains.clone();
    let cached = load_cfproxy_domains_from_cache();
    let defaults = default_cfproxy_domains();
    let mut merged = Vec::new();
    merged.extend(user.iter().cloned());
    merged.extend(pool.iter().cloned());
    merged.extend(cached.iter().cloned());
    merged.extend(defaults.iter().cloned());
    let merged = {
        let mut seen = std::collections::HashSet::new();
        merged
            .into_iter()
            .filter(|d| seen.insert(d.clone()))
            .collect::<Vec<_>>()
    };

    {
        let mut cfg = CFPROXY.write();
        cfg.domains = merged.clone();
    }
    crate::balancer::BALANCER
        .write()
        .update_domains_list_with_priority(user.len(), &merged);
    save_cfproxy_domains_to_cache(&pool);
    linfo!(
        " CF: список доменов обновлен ({} из {} источников, {} в пуле)",
        pool.len(),
        sources_used,
        merged.len()
    );
    true
}

// ---------------------------------------------------------------------------
// DNS over HTTPS (DoH) resolve
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DohAnswer {
    #[serde(rename = "data")]
    data: String,
    #[serde(rename = "type")]
    type_: i32,
}
#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer", default)]
    answer: Vec<DohAnswer>,
}

static DOH_CACHE: Lazy<parking_lot::RwLock<std::collections::HashMap<String, (String, Instant)>>> =
    Lazy::new(|| parking_lot::RwLock::new(std::collections::HashMap::new()));

fn pick_preferred_ip(candidates: &[String]) -> String {
    let mut fallback_v6 = String::new();
    for c in candidates {
        let c = c.trim();
        if let Ok(ip) = c.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(v4) => return v4.to_string(),
                std::net::IpAddr::V6(v6) => {
                    if fallback_v6.is_empty() {
                        fallback_v6 = v6.to_string();
                    }
                }
            }
        }
    }
    fallback_v6
}

pub async fn resolve_doh(domain: &str) -> Option<String> {
    if let Some((ip, exp)) = DOH_CACHE.read().get(domain).cloned() {
        if Instant::now() < exp {
            return Some(ip);
        }
    }

    let endpoints = [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/dns-query",
        "https://dns.quad9.net/dns-query",
        "https://dns.adguard-dns.com/dns-query",
    ];

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(1500))
        .build()
        .ok()?;

    let (tx, mut rx) = tokio::sync::mpsc::channel(endpoints.len() + 1);
    let mut tasks = Vec::new();

    for u in endpoints {
        let client = client.clone();
        let domain = domain.to_string();
        let tx = tx.clone();
        tasks.push(tokio::spawn(async move {
            let full = format!("{}?name={}&type=A", u, domain);
            if let Ok(resp) = client
                .get(&full)
                .header("Accept", "application/dns-json")
                .send()
                .await
            {
                if resp.status().as_u16() == 200 {
                    if let Ok(r) = resp.json::<DohResponse>().await {
                        for ans in r.answer {
                            if ans.type_ == 1 {
                                let _ = tx.send(Some(ans.data)).await;
                                return;
                            }
                        }
                    }
                }
            }
            let _ = tx.send(None).await;
        }));
    }

    // UDP-резолв через системный resolver как дополнительный кандидат
    {
        let domain2 = domain.to_string();
        let tx = tx.clone();
        tasks.push(tokio::spawn(async move {
            let host = format!("{}:443", domain2);
            if let Ok(Ok(addrs)) = tokio::time::timeout(
                Duration::from_millis(1500),
                tokio::net::lookup_host(host),
            )
            .await
            {
                let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                let p = pick_preferred_ip(&ips);
                if !p.is_empty() {
                    let _ = tx.send(Some(p)).await;
                    return;
                }
            }
            let _ = tx.send(None).await;
        }));
    }

    drop(tx); // Чтобы rx.recv() завершился, когда все таски завершатся

    let deadline = tokio::time::sleep(Duration::from_millis(1500));
    tokio::pin!(deadline);

    let mut final_ip = None;
    loop {
        tokio::select! {
            _ = &mut deadline => {
                break;
            }
            msg = rx.recv() => {
                match msg {
                    Some(Some(ip)) => {
                        final_ip = Some(ip);
                        break;
                    }
                    Some(None) => {} // Таска ничего не нашла
                    None => break,   // Все таски завершились
                }
            }
        }
    }

    // Отменяем все незавершенные фоновые таски (исправление утечки)
    for t in tasks {
        t.abort();
    }

    if let Some(ip) = &final_ip {
        DOH_CACHE.write().insert(
            domain.to_string(),
            (ip.clone(), Instant::now() + Duration::from_secs(300)),
        );
    }
    
    final_ip
}

// ---------------------------------------------------------------------------
// cfConnectDomain
// ---------------------------------------------------------------------------

fn new_timed_attempt_timeout(base: Duration, phase: Duration) -> Duration {
    let mut eff = base;
    if eff <= Duration::ZERO {
        eff = Duration::from_secs(5);
    }
    if eff > phase {
        eff = phase;
    }
    eff
}

pub async fn cf_connect_domain(
    domain: &str,
    path: &str,
    timeout: f64,
) -> (Option<RawWebSocket>, String, Option<WsError>) {
    let path = if path.is_empty() { "/apiws" } else { path };

    let attempt_timeout = crate::ws::ws_connect_timeout(timeout);
    let mut phase_timeout = attempt_timeout;
    if phase_timeout > CFPROXY_DIAL_PHASE_TIMEOUT {
        phase_timeout = CFPROXY_DIAL_PHASE_TIMEOUT;
    }

    let host_timeout = new_timed_attempt_timeout(phase_timeout, phase_timeout);
    match ws_connect_once(domain, domain, path, host_timeout).await {
        Ok(ws) => return (Some(ws), String::new(), None),
        Err(host_err) => {
            if is_http_status_error(&host_err, 429) {
                return (None, String::new(), Some(host_err));
            }
            let resolved_ip = resolve_doh(domain).await.unwrap_or_default();
            if resolved_ip.is_empty() {
                ldebug!(" CF DNS {} -> no result", domain);
                return (None, String::new(), Some(host_err));
            }
            ldebug!(" CF DNS {} -> {}", domain, resolved_ip);
            let ip_timeout = new_timed_attempt_timeout(phase_timeout, phase_timeout);
            match ws_connect_once(&resolved_ip, domain, path, ip_timeout).await {
                Ok(ws) => (Some(ws), resolved_ip, None),
                Err(e) => (None, resolved_ip, Some(e)),
            }
        }
    }
}

pub fn log_cf_conn_error(msg: &str, err: &WsError) {
    if let WsError::Io(e) = err {
        if e.kind() == std::io::ErrorKind::ConnectionReset {
            return;
        }
    }
    if is_http_status_error(err, 429) {
        lwarn!("{}", msg);
    } else {
        lerror!("{}", msg);
    }
}

// активный домен set/save
pub fn set_active_domain_and_save(_chosen: &str) {
    // Больше не используется для файлов. Балансер обновляется внутри proxy.rs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_known_encoded_domain() {
        // virkgj.com -> известный encoded-домен из встроенного списка
        let d = decode_cf_domain("virkgj.com");
        assert!(d.ends_with(".co.uk"), "decoded = {}", d);
        assert_eq!(normalize_cf_domain("virkgj.com"), d);
    }

    #[test]
    fn pool_entry_encoded_and_plain() {
        // encoded .com декодируется
        let enc = canonicalize_pool_entry("virkgj.com").unwrap();
        assert!(enc.ends_with(".co.uk"));
        // обычный домен (в т.ч. вида my-proxy.example.org) берётся как есть
        assert_eq!(
            canonicalize_pool_entry("my-proxy.example.org").unwrap(),
            "my-proxy.example.org"
        );
        assert_eq!(
            canonicalize_pool_entry("EXAMPLE.ORG").unwrap(),
            "example.org"
        );
        assert!(canonicalize_pool_entry("not a domain!!").is_none());
        assert!(canonicalize_pool_entry("").is_none());
    }

    #[test]
    fn user_domains_as_is() {
        assert_eq!(
            canonicalize_user_domain("my-proxy.example.org").unwrap(),
            "my-proxy.example.org"
        );
        assert_eq!(
            canonicalize_user_domain("https://MyProxy.example.com/path").unwrap(),
            "myproxy.example.com"
        );
        assert_eq!(
            canonicalize_user_domain("myproxy.example.com:443").unwrap(),
            "myproxy.example.com"
        );
        // .com НЕ декодируется для пользовательских доменов
        assert_eq!(
            canonicalize_user_domain("virkgj.com").unwrap(),
            "virkgj.com"
        );
        assert!(canonicalize_user_domain("no").is_none());
        // Свой Cloudflare Worker: адрес можно вставлять целиком.
        assert_eq!(
            canonicalize_user_domain("my-worker.username.workers.dev").unwrap(),
            "my-worker.username.workers.dev"
        );
        assert_eq!(
            canonicalize_user_domain("https://my-worker.username.workers.dev/apiws?x=1").unwrap(),
            "my-worker.username.workers.dev"
        );
    }

    #[test]
    fn user_domain_merge_dedup() {
        let m = merge_user_domains(&[
            vec!["a.example.com".to_string(), "b.example.com".to_string()],
            vec!["A.example.com".to_string()],
        ]);
        assert_eq!(m, vec!["a.example.com".to_string(), "b.example.com".to_string()]);
    }
}