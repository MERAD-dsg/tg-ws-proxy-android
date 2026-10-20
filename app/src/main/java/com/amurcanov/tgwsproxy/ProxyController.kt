package com.amurcanov.tgwsproxy

import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.core.content.ContextCompat
import kotlinx.coroutines.flow.first

object ProxyController {

    suspend fun startFromSavedSettings(
        context: Context,
        showInvalidPortToast: Boolean = false
    ): Boolean {
        val settingsStore = SettingsStore(context)
        settingsStore.migrateLegacyDefaults()
        val portText = settingsStore.port.first()
        val port = portText.toIntOrNull()
        if (port == null) {
            if (showInvalidPortToast) {
                Toast.makeText(context, context.getString(R.string.invalid_port), Toast.LENGTH_SHORT).show()
            }
            ProxyTileService.requestSync(context)
            return false
        }

        val bindIp = settingsStore.bindIp.first()
        val isExperimental = settingsStore.isExperimentalMode.first()
        val isDcAuto = settingsStore.isDcAuto.first()
        val poolSize = settingsStore.poolSize.first()
        val cfEnabled = settingsStore.cfproxyEnabled.first()
        val customCfDomainEnabled = settingsStore.customCfDomainEnabled.first()
        val customCfDomain = settingsStore.customCfDomain.first().trim()
        val cfExtraUrls = settingsStore.cfproxyExtraUrls.first().trim()
        val cfWorkerDomains = settingsStore.cfWorkerDomains.first().trim()
        val dpiBypassEnabled = settingsStore.dpiBypassEnabled.first()
        val upstreamProxyUrl = settingsStore.upstreamProxyUrl.first().trim()
        val secretKey = ensureSecretKey(settingsStore)
        val secretHistory = settingsStore.secretHistory.first().trim()

        val parsedIps = buildList {
            if (!isDcAuto) {
                appendDc(1, settingsStore.dc1.first())
                appendDc(2, settingsStore.dc2.first())
                appendDc(3, settingsStore.dc3.first())
                appendDc(4, settingsStore.dc4.first())

                if (isExperimental) {
                    appendDc(5, settingsStore.dc5.first())
                    appendDc(203, settingsStore.dc203.first())
                    appendDc(-1, settingsStore.dc1m.first())
                    appendDc(-2, settingsStore.dc2m.first())
                    appendDc(-3, settingsStore.dc3m.first())
                    appendDc(-4, settingsStore.dc4m.first())
                    appendDc(-5, settingsStore.dc5m.first())
                    appendDc(-203, settingsStore.dc203m.first())
                }
            }
        }.joinToString(",")

        ContextCompat.startForegroundService(
            context,
            Intent(context, ProxyService::class.java).apply {
                action = ProxyService.ACTION_START
                putExtra(ProxyService.EXTRA_BIND_IP, bindIp)
                putExtra(ProxyService.EXTRA_PORT, port)
                putExtra(ProxyService.EXTRA_IPS, parsedIps)
                putExtra(ProxyService.EXTRA_POOL_SIZE, poolSize)
                putExtra(ProxyService.EXTRA_CFPROXY_ENABLED, cfEnabled)
                putExtra(ProxyService.EXTRA_CFPROXY_PRIORITY, true)
                putExtra(
                    ProxyService.EXTRA_CFPROXY_DOMAIN,
                    if (customCfDomainEnabled && cfEnabled) customCfDomain else ""
                )
                putExtra(ProxyService.EXTRA_CFPROXY_EXTRA_URLS, if (cfEnabled) cfExtraUrls else "")
                putExtra(
                    ProxyService.EXTRA_CF_WORKER_DOMAINS,
                    if (cfEnabled) cfWorkerDomains else ""
                )
                putExtra(ProxyService.EXTRA_DPI_BYPASS, dpiBypassEnabled)
                putExtra(ProxyService.EXTRA_UPSTREAM_PROXY, upstreamProxyUrl)
                putExtra(ProxyService.EXTRA_SECRET_KEY, secretKey)
                putExtra(ProxyService.EXTRA_SECRET_HISTORY, secretHistory)
            }
        )
        ProxyTileService.requestSync(context)
        return true
    }

    fun stop(context: Context) {
        context.startService(
            Intent(context, ProxyService::class.java).apply {
                action = ProxyService.ACTION_STOP
            }
        )
        ProxyTileService.requestSync(context)
    }

    private suspend fun ensureSecretKey(settingsStore: SettingsStore): String {
        // Атомарно: либо существующий корректный секрет, либо новый — ровно
        // тот, который сохранится, и который увидит пользователь.
        return settingsStore.getOrCreateSecret()
    }

    private fun MutableList<String>.appendDc(dc: Int, value: String) {
        val ip = value.trim()
        if (ip.isNotBlank()) {
            add("$dc:$ip")
        }
    }

}
