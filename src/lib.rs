pub mod cfproxy;
pub mod config;
pub mod crypto;
pub mod faketls;
pub mod net;
pub mod proxy;
pub mod ws;
pub mod balancer;

use config::*;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use proxy::{parse_cidr_pool, run_proxy, ProxyPools};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

// Глобальный рантайм — никогда не дропается
static RUNTIME: OnceCell<Runtime> = OnceCell::new();

struct ProxyState {
    pools: Arc<ProxyPools>,
    handle: tokio::task::JoinHandle<()>,
    cancel_tasks: CancellationToken,
}

static STATE: OnceCell<Mutex<Option<ProxyState>>> = OnceCell::new();

fn state_cell() -> &'static Mutex<Option<ProxyState>> {
    STATE.get_or_init(|| Mutex::new(None))
}

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        // Многопоточный рантайм, кол-во воркеров адекватно мобиле
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("tgwsproxy-rt")
            .enable_all()
            .build()
            .expect("failed to build global tokio runtime")
    })
}

fn cstr_to_string(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(p).to_string_lossy().into_owned() }
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

/// # Safety
/// Указатели должны быть валидными C-строками (или null).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn StartProxy(
    c_host: *const c_char,
    port: c_int,
    c_dc_ips: *const c_char,
    c_secret: *const c_char,
    verbose: c_int,
) -> c_int {
    let cell = state_cell();
    let mut guard = cell.lock();

    if guard.is_some() {
        return -1;
    }

    let host = cstr_to_string(c_host);
    let go_port = port as u16;
    let dc_ips_str = cstr_to_string(c_dc_ips);
    let secret_str = cstr_to_string(c_secret);
    let is_verbose = verbose != 0;

    init_logging(is_verbose);
    cfproxy::clear_cfproxy_429_cooldowns();

    if secret_str.len() == 32 {
        if hex::decode(&secret_str).is_ok() {
            *PROXY_SECRET.write() = secret_str.clone();
        }
    }

    cfproxy::init_cfproxy_domains();

    let dc_opt_map: HashMap<i32, String> = parse_cidr_pool(&dc_ips_str);

    let rt = runtime();
    let cancel_tasks = CancellationToken::new();
    let pools = Arc::new(ProxyPools::new(cancel_tasks.clone()));

    // Канал готовности: ждём успешного bind перед возвратом
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();

    let pools_task = pools.clone();
    let host_task = host.clone();
    let map_task = dc_opt_map.clone();
    let cancel_root = cancel_tasks.clone();

    let handle = rt.spawn(async move {
        // Фоновое обновление пула доменов (GitHub + зеркала + пользовательские
        // URL). Раньше оно не запускалось вовсе — пул устаревал и «умирал».
        cfproxy::start_cfproxy_refresh();

        // Предварительный bind для сигнала готовности
        let addr = format!("{}:{}", host_task, go_port);
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => {
                let _ = tx.send(Ok(()));
                if let Err(e) =
                    run_proxy(pools_task, host_task, go_port, map_task, cancel_root, listener).await
                {
                    lerror!("listen on {}: {}", addr, e);
                }
            }
            Err(e) => {
                let _ = tx.send(Err(format!("listen on {}: {}", addr, e)));
            }
        }
    });

    // Ждём результат bind
    match rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            handle.abort();
            return -3;
        }
        Err(_) => {
            handle.abort();
            return -3;
        }
    }

    *guard = Some(ProxyState {
        pools,
        handle,
        cancel_tasks,
    });

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn StopProxy() -> c_int {
    let cell = state_cell();
    let mut guard = cell.lock();

    let state = match guard.take() {
        Some(s) => s,
        None => return -1,
    };

    // graceful shutdown — НЕ дропаем рантайм
    linfo!("StopProxy: cancelling all tasks");
    state.cancel_tasks.cancel();

    let rt = runtime();
    let pools = state.pools.clone();
    let handle = state.handle;
    rt.block_on(async move {
        linfo!("StopProxy: waiting for proxy tasks to finish (max 2s)");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        linfo!("StopProxy: closing pool connections");
        pools.close_all().await;
        pools.reset().await;
        linfo!("StopProxy: done");
    });

    STATS.reset();
    WS_BLACKLIST.write().clear();
    DC_FAIL_UNTIL.write().clear();
    IP_FAIL_UNTIL.write().clear();
    cfproxy::clear_cfproxy_429_cooldowns();
    proxy::set_ws_pool_fronting_first(true);

    linfo!("StopProxy: exit");
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn SetPoolSize(size: c_int) {
    // Оригинал: pool_size = max(0, N); 0 отключает преконнект пула.
    let mut n = size;
    if n < 0 {
        n = 0;
    }
    if n > 16 {
        n = 16;
    }
    POOL_SIZE.store(n, Ordering::Relaxed);
}

#[unsafe(no_mangle)]
pub extern "C" fn SetBufferSizeKb(kb: c_int) {
    // proxy --buf-kb: размер SO_RCVBUF/SO_SNDBUF, минимум 4KB.
    let mut n = kb;
    if n < 4 {
        n = 4;
    }
    if n > 4096 {
        n = 4096;
    }
    BUFFER_SIZE.store(n * 1024, Ordering::Relaxed);
    RECV_BUF.store(n * 1024, Ordering::Relaxed);
    SEND_BUF.store(n * 1024, Ordering::Relaxed);
}

/// # Safety
/// `c_cache_dir` — валидная C-строка или null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SetCfProxyCacheDir(c_cache_dir: *const c_char) {
    let dir = cstr_to_string(c_cache_dir);
    CFPROXY.write().cache_dir = dir.trim().to_string();
}

/// # Safety
/// `c_user_domain` — валидная C-строка или null (можно списком через , ; пробел).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SetCfProxyConfig(
    enabled: c_int,
    _priority: c_int,
    c_user_domain: *const c_char,
) {
    CFPROXY_ENABLED.store(enabled != 0, Ordering::Relaxed);
    let user_domain = cstr_to_string(c_user_domain);
    // Пользовательские домены используются КАК ЕСТЬ (my-proxy.example.com и т.п.),
    // без decode .com -> .co.uk и без требования суффикса .co.uk.
    let list = coerce_domain_list_str(&user_domain);
    let user_domains = crate::cfproxy::merge_user_domains(&[list]);
    let mut cfg = CFPROXY.write();
    cfg.user_domain = user_domain.trim().to_string();
    cfg.user_domains = user_domains.clone();
    if !user_domains.is_empty() {
        // Приоритет пользователя: его домены идут первыми, авто-пул — запасной.
        let mut domains = user_domains.clone();
        for d in cfg.domains.iter() {
            if !domains.contains(d) {
                domains.push(d.clone());
            }
        }
        cfg.domains = domains.clone();
        cfg.active = user_domains[0].clone();
        crate::balancer::BALANCER
            .write()
            .update_domains_list_with_priority(user_domains.len(), &domains);
        linfo!(
            " CF: пользовательские домены заданы ({}): {:?}",
            user_domains.len(),
            user_domains
        );
    }
}

/// # Safety
/// `c_urls` — валидная C-строка или null: URL списков доменов через , ; пробел.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SetCfProxyExtraUrls(c_urls: *const c_char) {
    let raw = cstr_to_string(c_urls);
    let urls: Vec<String> = raw
        .replace(',', " ")
        .replace(';', " ")
        .split_whitespace()
        .map(|s| s.trim().to_string())
        .filter(|s| s.starts_with("http://") || s.starts_with("https://"))
        .collect();
    *CFPROXY_EXTRA_URLS.write() = urls;
}

/// # Safety
/// `c_url` — валидная C-строка или null: `socks5://user:pass@host:port`
/// или `http://host:port`. Пусто — прямые соединения.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SetUpstreamProxy(c_url: *const c_char) {
    let url = cstr_to_string(c_url);
    let url = url.trim().to_string();
    if !url.is_empty() {
        match crate::net::parse_upstream_url(&url) {
            Ok(p) => {
                linfo!(
                    " upstream proxy: {:?}://{}:{} (auth={})",
                    p.kind,
                    p.host,
                    p.port,
                    if p.username.is_empty() { "no" } else { "yes" }
                );
            }
            Err(e) => {
                lwarn!(" upstream proxy url ignored: {}", e);
                return;
            }
        }
    }
    *UPSTREAM_PROXY_URL.write() = url;
}

/// Обход DPI: фрагментация первого TCP-сегмента (TLS ClientHello).
#[unsafe(no_mangle)]
pub extern "C" fn SetDpiBypass(enabled: c_int, frag_size: c_int, frag_delay_ms: c_int) {
    DPI_BYPASS_ENABLED.store(enabled != 0, Ordering::Relaxed);
    let mut size = frag_size;
    if size < 1 {
        size = 1;
    }
    if size > 256 {
        size = 256;
    }
    DPI_FRAG_SIZE.store(size, Ordering::Relaxed);
    let mut delay = frag_delay_ms;
    if delay < 0 {
        delay = 0;
    }
    if delay > 1000 {
        delay = 1000;
    }
    DPI_FRAG_DELAY_MS.store(delay, Ordering::Relaxed);
}

/// Сводка по пулу доменов (для отчётов/диагностики).
#[unsafe(no_mangle)]
pub extern "C" fn GetDomainsSummary() -> *mut c_char {
    let (total, user, cooling) = {
        let cfg = CFPROXY.read();
        let total = cfg.domains.len();
        let user = cfg.user_domains.len();
        drop(cfg);
        let cooling = crate::config::DOMAIN_FAIL
            .read()
            .values()
            .filter(|s| {
                s.until
                    .map(|u| u > std::time::Instant::now())
                    .unwrap_or(false)
            })
            .count();
        (total, user, cooling)
    };
    let upstream = {
        let u = UPSTREAM_PROXY_URL.read();
        if u.trim().is_empty() {
            "direct".to_string()
        } else {
            "upstream".to_string()
        }
    };
    let s = format!("domains={} user={} cooldown={} route={}", total, user, cooling, upstream);
    CString::new(s).unwrap_or_default().into_raw()
}

/// # Safety
/// `c_domains` — валидная C-строка или null (--cfproxy-worker-domain, repeatable).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SetCfWorkerDomains(c_domains: *const c_char) {
    let raw = cstr_to_string(c_domains);
    // Пользователь часто вставляет адрес целиком (https://…workers.dev/),
    // поэтому нормализуем: схема/путь/порт отбрасываются, домен валидируется.
    let mut domains: Vec<String> = Vec::new();
    for item in coerce_domain_list_str(&raw) {
        match crate::config::canonicalize_user_domain(&item) {
            Some(d) => {
                if !domains.contains(&d) {
                    domains.push(d);
                }
            }
            None => lwarn!(" worker: домен проигнорирован (некорректный): {}", item),
        }
    }
    if !domains.is_empty() {
        linfo!(" CF worker: задано доменов: {:?}", domains);
        *CF_WORKER_DOMAINS.write() = domains;
    } else if raw.trim().is_empty() {
        *CF_WORKER_DOMAINS.write() = Vec::new();
    }
}

/// # Safety
/// `c_domain` — валидная C-строка или null (--fake-tls-domain, ee-secret).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SetFakeTlsDomain(c_domain: *const c_char) {
    let d = cstr_to_string(c_domain);
    *FAKE_TLS_DOMAIN.write() = d.trim().to_string();
}

#[unsafe(no_mangle)]
pub extern "C" fn SetDisableSecure(v: c_int) {
    // --no-secure: порт 80 для CF proxy/worker.
    DISABLE_SECURE.store(v != 0, Ordering::Relaxed);
}

#[unsafe(no_mangle)]
pub extern "C" fn SetForceTestDc(v: c_int) {
    // --force-test-dc: весь трафик на тестовые DC.
    FORCE_TEST_DC.store(v != 0, Ordering::Relaxed);
}

#[unsafe(no_mangle)]
pub extern "C" fn SetProxyProtocol(v: c_int) {
    // --proxy-protocol: принимать PROXY protocol v1.
    PROXY_PROTOCOL.store(v != 0, Ordering::Relaxed);
}

/// # Safety
/// `c_secret` — валидная C-строка или null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SetSecret(c_secret: *const c_char) {
    let s = cstr_to_string(c_secret);
    if s.len() != 32 {
        return;
    }
    if hex::decode(&s).is_err() {
        return;
    }
    *PROXY_SECRET.write() = s;
}

#[unsafe(no_mangle)]
pub extern "C" fn GetStats() -> *mut c_char {
    let s = STATS.summary();
    CString::new(s).unwrap_or_default().into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn GetSecretWithPrefix() -> *mut c_char {
    // ee-secret при включённом FakeTLS: ee{secret}{domain_hex} — как в оригинале.
    let sec = PROXY_SECRET.read().clone();
    let ftls = FAKE_TLS_DOMAIN.read().clone();
    let full = if ftls.is_empty() {
        format!("dd{}", sec)
    } else {
        format!("ee{}{}", sec, ftls.as_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>())
    };
    CString::new(full).unwrap_or_default().into_raw()
}

/// # Safety
/// `p` должен быть указателем, ранее возвращённым из этой библиотеки.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn FreeString(p: *mut c_char) {
    if p.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(p);
    }
}
