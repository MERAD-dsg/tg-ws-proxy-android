use crate::config::*;
use crate::{ldebug, lwarn};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// Исходящие соединения: прямые или через SOCKS5/HTTP-апстрим.
//
// Апстрим — это «обход без VpnService»: например, локальный SOCKS5-шлюз
// поверх Cloudflare WARP (запущенный на ПК/роутере/в другом приложении),
// любой публичный socks5/http прокси. Соединения прокси идут через него,
// VpnService Android при этом не нужен. Если апстрим недоступен — автоматически
// падаем на прямое подключение.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamKind {
    Socks5,
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamProxy {
    pub kind: UpstreamKind,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

/// Разбор `socks5://user:pass@host:port` / `http://host:port`.
/// Без схемы по умолчанию считается socks5. Порт необязателен
/// (1080 для socks5, 8080 для http).
pub fn parse_upstream_url(url: &str) -> Result<UpstreamProxy, String> {
    let raw = url.trim();
    if raw.is_empty() {
        return Err("empty url".to_string());
    }
    let (scheme, rest) = match raw.find("://") {
        Some(i) => (raw[..i].to_ascii_lowercase(), &raw[i + 3..]),
        None => ("socks5".to_string(), raw),
    };
    let kind = match scheme.as_str() {
        "socks5" | "socks5h" | "socks" => UpstreamKind::Socks5,
        "http" | "https" => UpstreamKind::Http,
        _ => return Err(format!("unsupported scheme: {}", scheme)),
    };
    let rest = rest.trim().trim_end_matches('/');
    let (auth, hostport) = match rest.rfind('@') {
        Some(i) => (Some(&rest[..i]), &rest[i + 1..]),
        None => (None, rest),
    };
    let (username, password) = match auth {
        Some(a) => match a.find(':') {
            Some(i) => (a[..i].to_string(), a[i + 1..].to_string()),
            None => (a.to_string(), String::new()),
        },
        None => (String::new(), String::new()),
    };
    let def_port = match kind {
        UpstreamKind::Socks5 => 1080,
        UpstreamKind::Http => 8080,
    };
    let (host, port) = split_hostport(hostport, Some(def_port))?;
    if host.is_empty() {
        return Err("empty host".to_string());
    }
    Ok(UpstreamProxy {
        kind,
        host,
        port,
        username,
        password,
    })
}

/// Разбор `host:port` (порт строго обязателен, если default=None).
pub fn split_hostport(s: &str, default: Option<u16>) -> Result<(String, u16), String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty host".to_string());
    }
    if let Some(stripped) = s.strip_prefix('[') {
        // [ipv6]:port
        match stripped.find(']') {
            Some(e) => {
                let host = stripped[..e].to_string();
                let rest = &stripped[e + 1..];
                let port = match rest.strip_prefix(':') {
                    Some(p) => p
                        .parse::<u16>()
                        .map_err(|_| format!("bad port: {}", p))?,
                    None => default.ok_or_else(|| "port required".to_string())?,
                };
                return Ok((host, port));
            }
            None => return Err("bad ipv6 literal".to_string()),
        }
    }
    match s.rfind(':') {
        Some(i) if i > 0 && !s[i + 1..].is_empty() && s[i + 1..].chars().all(|c| c.is_ascii_digit()) => {
            let port = s[i + 1..]
                .parse::<u16>()
                .map_err(|_| format!("bad port: {}", &s[i + 1..]))?;
            Ok((s[..i].to_string(), port))
        }
        _ => {
            let port = default.ok_or_else(|| "port required".to_string())?;
            Ok((s.to_string(), port))
        }
    }
}

pub fn upstream_from_config() -> Option<UpstreamProxy> {
    let url = UPSTREAM_PROXY_URL.read().trim().to_string();
    if url.is_empty() {
        return None;
    }
    match parse_upstream_url(&url) {
        Ok(p) => Some(p),
        Err(e) => {
            lwarn!(" upstream proxy ignored: {}", e);
            None
        }
    }
}

fn io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg.to_string())
}

/// Открыть TCP к `target` ("host:port") — через апстрим, либо напрямую.
/// При ошибке апстрима автоматически падаем на прямое соединение.
pub async fn outbound_tcp(target: &str, timeout: Duration) -> std::io::Result<TcpStream> {
    if let Some(p) = upstream_from_config() {
        match tokio::time::timeout(timeout, connect_via(&p, target)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => {
                lwarn!(
                    " upstream {:?}://{}:{} failed for {}: {}; falling back to direct",
                    p.kind,
                    p.host,
                    p.port,
                    target,
                    e
                );
            }
            Err(_) => {
                lwarn!(
                    " upstream {:?}://{}:{} timed out for {}; falling back to direct",
                    p.kind,
                    p.host,
                    p.port,
                    target
                );
            }
        }
    }
    match tokio::time::timeout(timeout, TcpStream::connect(target)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "connect timeout",
        )),
    }
}

async fn connect_via(p: &UpstreamProxy, target: &str) -> std::io::Result<TcpStream> {
    let (host, port) = split_hostport(target, None).map_err(|e| io_err(&e))?;
    match p.kind {
        UpstreamKind::Socks5 => socks5_connect(p, &host, port).await,
        UpstreamKind::Http => http_connect(p, &host, port).await,
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 (RFC 1928 + RFC 1929 username/password)
// ---------------------------------------------------------------------------

pub async fn socks5_connect(p: &UpstreamProxy, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect((p.host.as_str(), p.port)).await?;
    s.set_nodelay(true)?;

    // greeting
    if p.username.is_empty() {
        s.write_all(&[0x05, 0x01, 0x00]).await?;
    } else {
        s.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    }
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    if resp[0] != 0x05 {
        return Err(io_err("socks5: bad version in greeting"));
    }
    match resp[1] {
        0x00 => {}
        0x02 => {
            if p.username.is_empty() {
                return Err(io_err("socks5: auth required but no credentials"));
            }
            let u = p.username.as_bytes();
            let pw = p.password.as_bytes();
            if u.len() > 255 || pw.len() > 255 {
                return Err(io_err("socks5: credentials too long"));
            }
            let mut req = Vec::with_capacity(3 + u.len() + pw.len());
            req.push(0x01);
            req.push(u.len() as u8);
            req.extend_from_slice(u);
            req.push(pw.len() as u8);
            req.extend_from_slice(pw);
            s.write_all(&req).await?;
            let mut r = [0u8; 2];
            s.read_exact(&mut r).await?;
            if r[1] != 0x00 {
                return Err(io_err("socks5: authentication failed"));
            }
        }
        0xFF => return Err(io_err("socks5: no acceptable auth methods")),
        m => return Err(io_err(&format!("socks5: unsupported auth method {}", m))),
    }

    // connect request
    let mut req = vec![0x05u8, 0x01, 0x00];
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        req.push(0x04);
        req.extend_from_slice(&ip.octets());
    } else {
        let hb = host.as_bytes();
        if hb.is_empty() || hb.len() > 255 {
            return Err(io_err("socks5: bad hostname"));
        }
        req.push(0x03);
        req.push(hb.len() as u8);
        req.extend_from_slice(hb);
    }
    req.push((port >> 8) as u8);
    req.push((port & 0xff) as u8);
    s.write_all(&req).await?;

    // reply
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(io_err("socks5: bad version in reply"));
    }
    if head[1] != 0x00 {
        let why = match head[1] {
            0x01 => "general failure",
            0x02 => "connection not allowed",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "ttl expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown error",
        };
        return Err(io_err(&format!("socks5: connect failed: {}", why)));
    }
    match head[3] {
        0x01 => {
            let mut b = [0u8; 6];
            s.read_exact(&mut b).await?;
        }
        0x04 => {
            let mut b = [0u8; 18];
            s.read_exact(&mut b).await?;
        }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            let mut b = vec![0u8; l[0] as usize + 2];
            s.read_exact(&mut b).await?;
        }
        _ => return Err(io_err("socks5: bad address type in reply")),
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// HTTP CONNECT
// ---------------------------------------------------------------------------

pub async fn http_connect(p: &UpstreamProxy, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect((p.host.as_str(), p.port)).await?;
    s.set_nodelay(true)?;
    let mut req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n",
        host, port, host, port
    );
    if !p.username.is_empty() {
        use base64::Engine;
        let token = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", p.username, p.password));
        req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", token));
    }
    req.push_str("Proxy-Connection: keep-alive\r\n\r\n");
    s.write_all(req.as_bytes()).await?;

    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut tmp = [0u8; 1];
    loop {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            return Err(io_err("http proxy: eof during CONNECT response"));
        }
        buf.push(tmp[0]);
        if buf.len() > 8192 {
            return Err(io_err("http proxy: CONNECT response too large"));
        }
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let status = text.split_whitespace().nth(1).unwrap_or("");
    if status != "200" {
        return Err(io_err(&format!("http proxy: CONNECT status {}", status)));
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// FragmentingStream — обход DPI по SNI/первому сегменту.
//
// Первый write (TLS ClientHello / HTTP-заголовок) разбивается на маленькие
// TCP-сегменты с паузой: DPI, читающий SNI только из первого сегмента,
// не успевает идентифицировать соединение и не обрывает его. Тактика
// известна как split/fragment (zapret, GoodbyeDPI) и работает без
// каких-либо внешних сервисов и без VpnService.
// ---------------------------------------------------------------------------

enum FragState {
    /// Ещё ничего не писали: первый write будет обрезан до first_chunk байт.
    Split,
    /// Первая часть ушла, ждём паузу перед остатком.
    Waiting(Pin<Box<tokio::time::Sleep>>),
    /// Обычный проход.
    Passthrough,
}

pub struct FragmentingStream {
    inner: TcpStream,
    state: FragState,
    first_chunk: usize,
    delay: Duration,
}

impl FragmentingStream {
    pub fn wrap(inner: TcpStream) -> Self {
        if DPI_BYPASS_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
            let chunk = DPI_FRAG_SIZE.load(std::sync::atomic::Ordering::Relaxed);
            let chunk = if chunk < 1 { 1 } else { chunk as usize };
            let delay = DPI_FRAG_DELAY_MS.load(std::sync::atomic::Ordering::Relaxed);
            let delay = if delay < 0 { 0 } else { delay as u64 };
            FragmentingStream {
                inner,
                state: FragState::Split,
                first_chunk: chunk,
                delay: Duration::from_millis(delay),
            }
        } else {
            FragmentingStream {
                inner,
                state: FragState::Passthrough,
                first_chunk: 0,
                delay: Duration::ZERO,
            }
        }
    }

    pub fn into_inner(self) -> TcpStream {
        self.inner
    }
}

impl AsyncRead for FragmentingStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FragmentingStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        match &mut me.state {
            FragState::Passthrough => Pin::new(&mut me.inner).poll_write(cx, buf),
            FragState::Split => {
                if buf.len() <= me.first_chunk {
                    let r = Pin::new(&mut me.inner).poll_write(cx, buf);
                    if let Poll::Ready(Ok(_)) = r {
                        me.state = FragState::Passthrough;
                    }
                    return r;
                }
                let n = me.first_chunk.max(1);
                match Pin::new(&mut me.inner).poll_write(cx, &buf[..n]) {
                    Poll::Ready(Ok(w)) => {
                        me.state = FragState::Waiting(Box::pin(tokio::time::sleep(me.delay)));
                        Poll::Ready(Ok(w))
                    }
                    other => other,
                }
            }
            FragState::Waiting(sleep) => match sleep.as_mut().poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(()) => {
                    me.state = FragState::Passthrough;
                    Pin::new(&mut me.inner).poll_write(cx, buf)
                }
            },
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Tests — гоняются на хосте через `cargo test`
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_upstream_variants() {
        let p = parse_upstream_url("socks5://user:pass@127.0.0.1:1080").unwrap();
        assert_eq!(p.kind, UpstreamKind::Socks5);
        assert_eq!(p.host, "127.0.0.1");
        assert_eq!(p.port, 1080);
        assert_eq!(p.username, "user");
        assert_eq!(p.password, "pass");

        let p = parse_upstream_url("http://proxy.lan:3128").unwrap();
        assert_eq!(p.kind, UpstreamKind::Http);
        assert_eq!(p.port, 3128);
        assert!(p.username.is_empty());

        // без схемы и без порта
        let p = parse_upstream_url("10.0.0.2").unwrap();
        assert_eq!(p.kind, UpstreamKind::Socks5);
        assert_eq!(p.port, 1080);

        // socks5 с портом по умолчанию
        let p = parse_upstream_url("socks5://10.0.0.2").unwrap();
        assert_eq!(p.port, 1080);

        // http без порта
        let p = parse_upstream_url("http://10.0.0.2").unwrap();
        assert_eq!(p.port, 8080);

        assert!(parse_upstream_url("ftp://x").is_err());
        assert!(parse_upstream_url("").is_err());
    }

    #[test]
    fn split_hostport_cases() {
        assert_eq!(
            split_hostport("example.com:443", None).unwrap(),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            split_hostport("1.2.3.4:80", None).unwrap(),
            ("1.2.3.4".to_string(), 80)
        );
        assert_eq!(
            split_hostport("[::1]:1080", None).unwrap(),
            ("::1".to_string(), 1080)
        );
        assert_eq!(
            split_hostport("example.com", Some(1080)).unwrap(),
            ("example.com".to_string(), 1080)
        );
        assert!(split_hostport("example.com", None).is_err());
    }

    #[tokio::test]
    async fn socks5_handshake_with_local_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // greeting
            let mut g = [0u8; 3];
            sock.read_exact(&mut g).await.unwrap();
            assert_eq!(&g, &[0x05, 0x01, 0x00]);
            sock.write_all(&[0x05, 0x00]).await.unwrap();
            // request
            let mut head = [0u8; 5];
            sock.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0], 0x05);
            assert_eq!(head[1], 0x01);
            assert_eq!(head[3], 0x03); // domain
            let mut rest = vec![0u8; head[4] as usize + 2];
            sock.read_exact(&mut rest).await.unwrap();
            let host = String::from_utf8_lossy(&rest[..head[4] as usize]).to_string();
            assert_eq!(host, "example.org");
            let port = u16::from_be_bytes([rest[head[4] as usize], rest[head[4] as usize + 1]]);
            assert_eq!(port, 443);
            // reply success
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0, 0])
                .await
                .unwrap();
        });

        let p = UpstreamProxy {
            kind: UpstreamKind::Socks5,
            host: addr.ip().to_string(),
            port: addr.port(),
            username: String::new(),
            password: String::new(),
        };
        let s = socks5_connect(&p, "example.org", 443).await.unwrap();
        assert_eq!(s.peer_addr().unwrap(), addr);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn fragmenting_stream_splits_first_write() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // читаем ровно 4 байта
            let mut buf = [0u8; 4];
            sock.read_exact(&mut buf).await.unwrap();
            buf
        });

        let raw = TcpStream::connect(addr).await.unwrap();
        let mut frag = FragmentingStream::wrap(raw);
        // принудительно включаем сплит 1 байт + пауза
        frag.state = FragState::Split;
        frag.first_chunk = 1;
        frag.delay = Duration::from_millis(1);

        frag.write_all(&[1, 2, 3, 4]).await.unwrap();
        frag.flush().await.unwrap();
        let got = server.await.unwrap();
        assert_eq!(&got, &[1, 2, 3, 4]);
        drop(frag);
    }
}
