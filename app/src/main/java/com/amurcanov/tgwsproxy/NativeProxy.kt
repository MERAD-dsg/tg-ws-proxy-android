package com.amurcanov.tgwsproxy

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer

interface ProxyLibrary : Library {
    companion object {
        val INSTANCE = Native.load("tgwsproxy", ProxyLibrary::class.java) as ProxyLibrary
    }

    fun StartProxy(host: String, port: Int, dcIps: String, secret: String, verbose: Int): Int
    fun StopProxy(): Int
    fun SetPoolSize(size: Int)
    fun SetBufferSizeKb(kb: Int)
    fun SetCfProxyCacheDir(cacheDir: String)
    fun SetCfProxyConfig(enabled: Int, priority: Int, userDomain: String)
    fun SetCfProxyExtraUrls(urls: String)
    fun SetUpstreamProxy(url: String)
    fun SetDpiBypass(enabled: Int, fragSize: Int, fragDelayMs: Int)
    fun SetCfWorkerDomains(domains: String)
    fun SetFakeTlsDomain(domain: String)
    fun SetDisableSecure(v: Int)
    fun SetForceTestDc(v: Int)
    fun SetProxyProtocol(v: Int)
    fun GetSecretWithPrefix(): Pointer?
    fun SetSecretHistory(secrets: String)
    fun DiagnoseRoutes(dc: Int): Pointer?
    fun GetActiveSecret(): Pointer?
    fun VerifyClientSecret(secret: String): Int
    fun GetStats(): Pointer?
    fun GetDomainsSummary(): Pointer?
    fun FreeString(p: Pointer)
}

object NativeProxy {
    fun startProxy(host: String, port: Int, dcIps: String, secret: String, verbose: Int): Int {
        return ProxyLibrary.INSTANCE.StartProxy(host, port, dcIps, secret, verbose)
    }

    fun stopProxy(): Int {
        return ProxyLibrary.INSTANCE.StopProxy()
    }

    fun setPoolSize(size: Int) {
        ProxyLibrary.INSTANCE.SetPoolSize(size)
    }

    fun setBufferSizeKb(kb: Int) {
        ProxyLibrary.INSTANCE.SetBufferSizeKb(kb)
    }

    fun setCfProxyCacheDir(cacheDir: String) {
        ProxyLibrary.INSTANCE.SetCfProxyCacheDir(cacheDir)
    }

    fun setCfProxyConfig(enabled: Boolean, priority: Boolean, userDomain: String) {
        ProxyLibrary.INSTANCE.SetCfProxyConfig(
            if (enabled) 1 else 0,
            if (priority) 1 else 0,
            userDomain
        )
    }

    /** Extra plain-text domain list URLs (comma/semicolon/space separated). */
    fun setCfProxyExtraUrls(urls: String) {
        ProxyLibrary.INSTANCE.SetCfProxyExtraUrls(urls)
    }

    /**
     * Outbound SOCKS5/HTTP upstream for all proxy connections
     * (e.g. a SOCKS5 gateway in front of Cloudflare WARP). Empty = direct.
     */
    fun setUpstreamProxy(url: String) {
        ProxyLibrary.INSTANCE.SetUpstreamProxy(url)
    }

    /** DPI bypass: split the first TLS segment (ClientHello fragmentation). */
    fun setDpiBypass(enabled: Boolean, fragSize: Int = 1, fragDelayMs: Int = 25) {
        ProxyLibrary.INSTANCE.SetDpiBypass(
            if (enabled) 1 else 0,
            fragSize,
            fragDelayMs
        )
    }

    /** Diagnostics summary of the CF domain pool. */
    fun getDomainsSummary(): String? {
        val ptr = ProxyLibrary.INSTANCE.GetDomainsSummary() ?: return null
        val res = ptr.getString(0)
        ProxyLibrary.INSTANCE.FreeString(ptr)
        return res
    }

    fun setCfWorkerDomains(domains: String) {
        ProxyLibrary.INSTANCE.SetCfWorkerDomains(domains)
    }

    fun setFakeTlsDomain(domain: String) {
        ProxyLibrary.INSTANCE.SetFakeTlsDomain(domain)
    }

    fun setDisableSecure(v: Boolean) {
        ProxyLibrary.INSTANCE.SetDisableSecure(if (v) 1 else 0)
    }

    fun setForceTestDc(v: Boolean) {
        ProxyLibrary.INSTANCE.SetForceTestDc(if (v) 1 else 0)
    }

    fun setProxyProtocol(v: Boolean) {
        ProxyLibrary.INSTANCE.SetProxyProtocol(if (v) 1 else 0)
    }

    /** Returns the full secret with correct prefix (dd or ee+domain_hex) */
    fun getSecretWithPrefix(): String? {
        val ptr = ProxyLibrary.INSTANCE.GetSecretWithPrefix() ?: return null
        val res = ptr.getString(0)
        ProxyLibrary.INSTANCE.FreeString(ptr)
        return res
    }

    /** Недавние секреты (CSV): прокси принимает их наравне с активным. */
    fun setSecretHistory(secrets: String) {
        ProxyLibrary.INSTANCE.SetSecretHistory(secrets)
    }

    /**
     * Проверка маршрутов (прямой WS / свой worker / пул CF).
     * Возвращает короткую сводку; подробности пишутся в лог.
     */
    fun diagnoseRoutes(dc: Int = 2): String? {
        val ptr = ProxyLibrary.INSTANCE.DiagnoseRoutes(dc) ?: return null
        val res = ptr.getString(0)
        ProxyLibrary.INSTANCE.FreeString(ptr)
        return res
    }

    /** Секрет, с которым реально работает нативный прокси (32 hex). */
    fun getActiveSecret(): String? {
        val ptr = ProxyLibrary.INSTANCE.GetActiveSecret() ?: return null
        val res = ptr.getString(0)
        ProxyLibrary.INSTANCE.FreeString(ptr)
        return res
    }

    /**
     * Сверка секрета из UI с активным секретом прокси.
     * 1 — совпадает, 0 — не совпадает, -1 — некорректный формат.
     */
    fun verifyClientSecret(secret: String): Int {
        return ProxyLibrary.INSTANCE.VerifyClientSecret(secret)
    }

    fun getStats(): String? {
        val ptr = ProxyLibrary.INSTANCE.GetStats() ?: return null
        val res = ptr.getString(0)
        ProxyLibrary.INSTANCE.FreeString(ptr)
        return res
    }

    /**
     * Разобранная статистика движка — для главного экрана и уведомления.
     * Один вызов JNA вместо десятка `substringAfter` в UI-потоке.
     */
    fun readStats(): ProxyStats? = getStats()?.let { parseStats(it) }

    fun parseStats(raw: String): ProxyStats {
        fun num(key: String, def: Int = 0): Int {
            val idx = raw.indexOf("$key=")
            if (idx < 0) return def
            val start = idx + key.length + 1
            var end = start
            while (end < raw.length && (raw[end].isDigit() || raw[end] == '-')) end++
            return raw.substring(start, end).toIntOrNull() ?: def
        }

        fun size(key: String): String {
            val idx = raw.indexOf("$key=")
            if (idx < 0) return "0"
            val start = idx + key.length + 1
            var end = start
            while (end < raw.length && raw[end] != ' ') end++
            return raw.substring(start, end)
        }

        return ProxyStats(
            active = num("active"),
            pingMs = num("ping"),
            pingAvgMs = num("ping_avg"),
            deadSessions = num("dead"),
            route = num("route"),
            up = size("up"),
            down = size("down"),
            badHandshakes = num("bad"),
        )
    }
}

/** Снимок статистики нативного движка (см. Stats::summary в src/config.rs). */
data class ProxyStats(
    val active: Int,
    val pingMs: Int,
    val pingAvgMs: Int,
    val deadSessions: Int,
    val route: Int,
    val up: String,
    val down: String,
    val badHandshakes: Int,
) {
    /** 0 — не измеряли; показываем «—». */
    val hasPing: Boolean get() = pingAvgMs > 0 || pingMs > 0
}
