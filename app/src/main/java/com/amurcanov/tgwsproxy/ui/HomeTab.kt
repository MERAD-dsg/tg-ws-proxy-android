package com.amurcanov.tgwsproxy.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.widget.Toast
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.amurcanov.tgwsproxy.BuildConfig
import com.amurcanov.tgwsproxy.NativeProxy
import com.amurcanov.tgwsproxy.ProxyController
import com.amurcanov.tgwsproxy.ProxyService
import com.amurcanov.tgwsproxy.ProxyStats
import com.amurcanov.tgwsproxy.R
import com.amurcanov.tgwsproxy.SettingsStore
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Главный экран — сознательно минималистичный: одна кнопка питания,
 * состояние, живой пинг/маршрут и «Применить в Telegram».
 * Всё остальное (настройки, журнал, диагностика) — за иконками сверху.
 */
@Composable
fun HomeTab(
    settingsStore: SettingsStore,
    onOpenSettings: () -> Unit,
    onOpenLogs: () -> Unit,
) {
    val context = LocalContext.current
    val isRunning by ProxyService.isRunning.collectAsStateWithLifecycle()
    val isVerifiedRunning by ProxyService.isVerifiedRunning.collectAsStateWithLifecycle()
    val isReady by settingsStore.isReady.collectAsStateWithLifecycle(initialValue = false)
    val savedPort by settingsStore.port.collectAsStateWithLifecycle(initialValue = "1443")
    val savedBindIp by settingsStore.bindIp.collectAsStateWithLifecycle(initialValue = "127.0.0.1")
    val savedSecretKey by settingsStore.secretKey.collectAsStateWithLifecycle(initialValue = "LOADING")
    val scope = rememberCoroutineScope()

    var isStarting by remember { mutableStateOf(false) }
    var stats by remember { mutableStateOf<ProxyStats?>(null) }
    var secretMismatch by remember { mutableStateOf(false) }

    if (!isReady || savedSecretKey == "LOADING") {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator(
                modifier = Modifier.size(22.dp),
                strokeWidth = 2.dp,
                color = MaterialTheme.colorScheme.primary,
            )
        }
        return
    }

    LaunchedEffect(savedSecretKey) {
        if (savedSecretKey.isEmpty()) settingsStore.getOrCreateSecret()
    }
    LaunchedEffect(isVerifiedRunning, isRunning) {
        if (isVerifiedRunning || !isRunning) isStarting = false
    }

    // Живой пинг + маршрут: раз в секунду, только пока прокси работает,
    // чтобы не будить CPU впустую.
    LaunchedEffect(isRunning, isVerifiedRunning) {
        while (isRunning || isVerifiedRunning) {
            stats = runCatching { NativeProxy.readStats() }.getOrNull()
            delay(1000)
        }
        stats = null
    }
    LaunchedEffect(isRunning, isVerifiedRunning, savedSecretKey) {
        secretMismatch = if (isRunning || isVerifiedRunning) {
            runCatching { NativeProxy.verifyClientSecret(secretForUrl(savedSecretKey)) == 0 }
                .getOrDefault(false)
        } else {
            false
        }
    }

    val port = savedPort.toIntOrNull() ?: 1443
    val proxyUrl = "https://t.me/proxy?server=$savedBindIp&port=$port&secret=dd${secretForUrl(savedSecretKey)}"
    val active = isRunning || isStarting
    val buttonScale by animateFloatAsState(
        targetValue = if (active) 1f else 0.94f,
        animationSpec = tween(220),
        label = "power_scale",
    )
    val accent by animateColorAsState(
        targetValue = if (isVerifiedRunning) MaterialTheme.colorScheme.primary
        else MaterialTheme.colorScheme.onSurfaceVariant,
        animationSpec = tween(300),
        label = "power_color",
    )
    val statusText = when {
        isVerifiedRunning -> stringResource(R.string.status_connected)
        active -> stringResource(R.string.status_connecting)
        else -> stringResource(R.string.status_disconnected)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.height(8.dp))

        // Кнопка питания = единственный основной элемент управления.
        Box(
            modifier = Modifier
                .size(168.dp)
                .scale(buttonScale)
                .clip(CircleShape)
                .background(
                    if (active) MaterialTheme.colorScheme.primaryContainer
                    else MaterialTheme.colorScheme.surfaceVariant
                )
                .clickable {
                    if (active) {
                        ProxyController.stop(context)
                    } else if (!isStarting) {
                        isStarting = true
                        scope.launch {
                            val started = ProxyController.startFromSavedSettings(
                                context = context,
                                showInvalidPortToast = true,
                            )
                            if (!started) isStarting = false
                        }
                    }
                },
            contentAlignment = Alignment.Center,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    imageVector = Icons.Default.PowerSettingsNew,
                    contentDescription = statusText,
                    tint = accent,
                    modifier = Modifier.size(46.dp),
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = statusText,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.SemiBold,
                    color = accent,
                )
                Text(
                    text = ":$port",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        Spacer(Modifier.height(18.dp))

        // Мини-панель живой диагностики (пинг/маршрут), заменяет лишние экраны.
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            MiniMetric(
                label = stringResource(R.string.home_ping),
                value = pingText(stats),
                modifier = Modifier.weight(1f),
            )
            MiniMetric(
                label = stringResource(R.string.home_route),
                value = routeText(stats?.route),
                modifier = Modifier.weight(1f),
            )
            MiniMetric(
                label = stringResource(R.string.home_traffic),
                value = trafficText(stats),
                modifier = Modifier.weight(1f),
            )
        }

        if (secretMismatch) {
            Spacer(Modifier.height(12.dp))
            Surface(
                color = MaterialTheme.colorScheme.errorContainer,
                contentColor = MaterialTheme.colorScheme.onErrorContainer,
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Icon(Icons.Default.Warning, contentDescription = null, modifier = Modifier.size(18.dp))
                    Text(
                        text = stringResource(R.string.secret_mismatch_banner),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }

        Spacer(Modifier.height(18.dp))

        Button(
            onClick = { applyToTelegramPackages(context, proxyUrl) },
            enabled = isVerifiedRunning || isRunning,
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
            shape = RoundedCornerShape(20.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary,
            ),
        ) {
            Text(
                text = stringResource(R.string.apply_in_telegram),
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
        }

        Spacer(Modifier.height(8.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedMiniButton(
                text = stringResource(R.string.copy_link),
                showCopyIcon = true,
                modifier = Modifier.weight(1f),
            ) {
                val cb = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cb.setPrimaryClip(ClipData.newPlainText("Proxy", proxyUrl))
                Toast.makeText(context, context.getString(R.string.copied), Toast.LENGTH_SHORT).show()
            }
            OutlinedMiniButton(
                text = stringResource(R.string.nav_settings_short),
                modifier = Modifier.weight(1f),
                onClick = onOpenSettings,
            )
            OutlinedMiniButton(
                text = stringResource(R.string.nav_logs_short),
                modifier = Modifier.weight(1f),
                onClick = onOpenLogs,
            )
        }

        Spacer(Modifier.height(10.dp))
        Text(
            text = "v${BuildConfig.VERSION_NAME}",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
        )
        Spacer(Modifier.height(16.dp))
    }
}

private fun secretForUrl(raw: String): String {
    val v = raw.trim()
    return if (v.isNotEmpty() && v != "LOADING") v else "00000000000000000000000000000000"
}

private fun pingText(stats: ProxyStats?): String {
    val s = stats ?: return "—"
    if (!s.hasPing) return "—"
    val avg = s.pingAvgMs
    return if (avg > 0) "$avg ms" else "${s.pingMs} ms"
}

@Composable
private fun routeText(code: Int?): String = when (code) {
    1 -> stringResource(R.string.route_direct)
    2 -> stringResource(R.string.route_worker)
    3 -> stringResource(R.string.route_cf)
    4 -> stringResource(R.string.route_tcp)
    else -> "—"
}

private fun trafficText(stats: ProxyStats?): String {
    val s = stats ?: return "—"
    return "↑${s.up} ↓${s.down}"
}

@Composable
private fun MiniMetric(label: String, value: String, modifier: Modifier = Modifier) {
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.18f)),
    ) {
        Column(
            modifier = Modifier.padding(vertical = 10.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = value,
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                textAlign = TextAlign.Center,
            )
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
            )
        }
    }
}

@Composable
private fun OutlinedMiniButton(
    text: String,
    modifier: Modifier = Modifier,
    showCopyIcon: Boolean = false,
    onClick: () -> Unit,
) {
    Box(
        modifier = modifier
            .height(44.dp)
            .clip(RoundedCornerShape(16.dp))
            .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.6f))
            .border(
                1.dp,
                MaterialTheme.colorScheme.outline.copy(alpha = 0.28f),
                RoundedCornerShape(16.dp),
            )
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Box(contentAlignment = Alignment.Center) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                if (showCopyIcon) {
                    Icon(
                        Icons.Default.ContentCopy,
                        contentDescription = null,
                        modifier = Modifier.size(14.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text(
                    text = text,
                    style = MaterialTheme.typography.labelMedium,
                    maxLines = 1,
                )
            }
        }
    }
}

private val telegramPackages = listOf(
    "org.telegram.messenger",
    "com.radolyn.ayugram",
    "com.exteragram.messenger",
    "org.telegram.plus",
    "ir.ilmili.telegraph",
    "org.telegram.BifToGram",
    "tw.nekomimi.nekogram",
    "xyz.nextalone.nagram",
    "uz.unnarsx.cherrygram",
    "org.telegram.mdgram",
    "org.forkclient.messenger.beta",
    "app.nicegram",
    "top.qwq2333.nullgram",
    "com.iMe.android",
    "ru.dahl.messenger",
    "com.scriptsaz.litegram",
    "org.thunderdog.challegram",
)

internal fun applyToTelegramPackages(context: Context, url: String) {
    val pm = context.packageManager
    val available = telegramPackages.filter {
        try {
            pm.getPackageInfo(it, 0)
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }
    if (available.isEmpty()) {
        Toast.makeText(context, context.getString(R.string.no_clients_found), Toast.LENGTH_SHORT).show()
        return
    }
    val intents = available.map { pkg -> Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply { setPackage(pkg) } }
    val launch = if (intents.size == 1) {
        intents.first()
    } else {
        Intent.createChooser(intents.first(), context.getString(R.string.pick_client))
            .putExtra(Intent.EXTRA_INITIAL_INTENTS, intents.drop(1).toTypedArray())
    }
    launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    try {
        context.startActivity(launch)
    } catch (_: Exception) {
        Toast.makeText(context, context.getString(R.string.open_client_failed), Toast.LENGTH_SHORT).show()
    }
}
