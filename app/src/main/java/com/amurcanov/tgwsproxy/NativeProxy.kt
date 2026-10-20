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
}
