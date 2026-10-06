package com.android.zdtd.service.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.Dp
import com.android.zdtd.service.R
import com.android.zdtd.service.ZdtdActions
import com.android.zdtd.service.api.ApiModels
import kotlinx.coroutines.launch
import org.json.JSONObject

private data class AetherSettingUi(
  val tun: String = "aetun0",
  val socks5Port: Int = 2090,
  val protocol: String = "h2",
  val noize: String = "firewall",
  val scanMode: String = "balanced",
  val enableTor: Boolean = false,
  val enableMark: Boolean = true,
  val customArgs: String = "",
  val mtu: Int? = null,
  val tun2proxyLogLevel: String = "info",
  val aetherLogLevel: String = "info",
)

private fun parseAetherSetting(obj: JSONObject?): AetherSettingUi {
  val data = obj?.optJSONObject("data") ?: obj
  return AetherSettingUi(
    tun = data?.optString("tun", "aetun0")?.trim().orEmpty().ifBlank { "aetun0" },
    socks5Port = data?.optInt("socks5_port", 2090)?.takeIf { it in 1025..65535 } ?: 2090,
    protocol = data?.optString("protocol", "h2")?.trim().orEmpty().ifBlank { "h2" },
    noize = data?.optString("noize", "firewall")?.trim().orEmpty().ifBlank { "firewall" },
    scanMode = data?.optString("scan_mode", "balanced")?.trim().orEmpty().ifBlank { "balanced" },
    enableTor = data?.optBoolean("enable_tor", false) ?: false,
    enableMark = data?.optBoolean("enable_mark", true) ?: true,
    customArgs = data?.optString("custom_args", "")?.trim().orEmpty(),
    mtu = data?.optInt("mtu", 0)?.takeIf { it in 1280..9000 },
    tun2proxyLogLevel = data?.optString("tun2proxy_loglevel", "info")?.trim().orEmpty().ifBlank { "info" },
    aetherLogLevel = data?.optString("aether_loglevel", "info")?.trim().orEmpty().ifBlank { "info" },
  )
}

private fun AetherSettingUi.toJson(): JSONObject = JSONObject()
  .put("tun", tun.trim().ifBlank { "aetun0" })
  .put("socks5_port", socks5Port)
  .put("protocol", protocol.trim().ifBlank { "h2" })
  .put("noize", noize.trim().ifBlank { "firewall" })
  .put("scan_mode", scanMode.trim().ifBlank { "balanced" })
  .put("enable_tor", enableTor)
  .put("enable_mark", enableMark)
  .put("custom_args", customArgs.trim())
  .put("mtu", mtu ?: JSONObject.NULL)
  .put("tun2proxy_loglevel", tun2proxyLogLevel.trim().ifBlank { "info" })
  .put("aether_loglevel", aetherLogLevel.trim().ifBlank { "info" })

@Composable
fun AetherProfileScreen(
  programs: List<ApiModels.Program>,
  profile: String,
  actions: ZdtdActions,
  snackHost: SnackbarHostState,
  topContentPadding: Dp = 0.dp,
  bottomContentPadding: Dp = 0.dp,
) {
  val compact = rememberIsCompactWidth()
  val effectiveTopContentPadding = topContentPadding + 12.dp
  val effectiveBottomContentPadding = bottomContentPadding + if (compact) 12.dp else 16.dp
  val context = LocalContext.current
  val scope = rememberCoroutineScope()
  val program = programs.firstOrNull { it.id == "aether" }
  val prof = program?.profiles?.firstOrNull { it.name == profile }
  val basePath = "/api/programs/aether/profiles/$profile"
  val scroll = rememberScrollState()

  var setting by remember(profile) { mutableStateOf(AetherSettingUi()) }
  var loaded by remember(profile) { mutableStateOf(false) }
  var saving by remember(profile) { mutableStateOf(false) }
  var tab by remember(profile) { mutableStateOf(0) }

  var tunText by remember(profile) { mutableStateOf("aetun0") }
  var socksText by remember(profile) { mutableStateOf("2090") }
  var protocolText by remember(profile) { mutableStateOf("h2") }
  var noizeText by remember(profile) { mutableStateOf("firewall") }
  var scanModeText by remember(profile) { mutableStateOf("balanced") }
  var enableTorState by remember(profile) { mutableStateOf(false) }
  var enableMarkState by remember(profile) { mutableStateOf(true) }
  var customArgsText by remember(profile) { mutableStateOf("") }
  var mtuText by remember(profile) { mutableStateOf("") }
  var t2pLogText by remember(profile) { mutableStateOf("info") }
  var aetherLogText by remember(profile) { mutableStateOf("info") }

  fun showSnack(msg: String) { scope.launch { snackHost.showSnackbar(msg) } }

  fun draftSettingOrNull(): AetherSettingUi? {
    val socks = socksText.trim().toIntOrNull() ?: return null
    val mtu = mtuText.trim().takeIf { it.isNotEmpty() }?.toIntOrNull()
    return AetherSettingUi(
      tun = tunText.trim(),
      socks5Port = socks,
      protocol = protocolText.trim(),
      noize = noizeText.trim(),
      scanMode = scanModeText.trim(),
      enableTor = enableTorState,
      enableMark = enableMarkState,
      customArgs = customArgsText.trim(),
      mtu = mtu,
      tun2proxyLogLevel = t2pLogText.trim().ifBlank { "info" },
      aetherLogLevel = aetherLogText.trim().ifBlank { "info" },
    )
  }

  LaunchedEffect(profile) {
    actions.loadJsonData("$basePath/setting") { obj ->
      val s = parseAetherSetting(obj)
      setting = s
      tunText = s.tun
      socksText = s.socks5Port.toString()
      protocolText = s.protocol
      noizeText = s.noize
      scanModeText = s.scanMode
      enableTorState = s.enableTor
      enableMarkState = s.enableMark
      customArgsText = s.customArgs
      mtuText = s.mtu?.toString().orEmpty()
      t2pLogText = s.tun2proxyLogLevel
      aetherLogText = s.aetherLogLevel
      loaded = true
    }
  }

  fun saveSettings() {
    val socks = socksText.trim().toIntOrNull()
    val mtu = mtuText.trim().takeIf { it.isNotEmpty() }?.toIntOrNull()
    when {
      tunText.trim().isEmpty() -> showSnack("TUN interface is required")
      socks == null || socks !in 1025..65535 -> showSnack("SOCKS5 port must be 1025..65535")
      mtuText.trim().isNotEmpty() && (mtu == null || mtu !in 1280..9000) -> showSnack("MTU must be empty or 1280..9000")
      else -> {
        val next = AetherSettingUi(
          tun = tunText.trim(),
          socks5Port = socks,
          protocol = protocolText.trim().ifBlank { "h2" },
          noize = noizeText.trim(),
          scanMode = scanModeText.trim(),
          enableTor = enableTorState,
          enableMark = enableMarkState,
          customArgs = customArgsText.trim(),
          mtu = mtu,
          tun2proxyLogLevel = t2pLogText.trim().ifBlank { "info" },
          aetherLogLevel = aetherLogText.trim().ifBlank { "info" },
        )
        saving = true
        actions.saveJsonData("$basePath/setting", next.toJson()) { ok ->
          saving = false
          if (ok) {
            setting = next
            showSnack(context.getString(R.string.saved))
          } else {
            showSnack(context.getString(R.string.save_failed))
          }
        }
      }
    }
  }

  val settingsDraft = draftSettingOrNull()
  val settingsDirty = loaded && settingsDraft != null && settingsDraft != setting

  Column(
    Modifier
      .fillMaxSize()
      .verticalScroll(scroll)
      .padding(horizontal = if (compact) 12.dp else 16.dp),
    verticalArrangement = Arrangement.spacedBy(12.dp),
  ) {
    Spacer(Modifier.height(effectiveTopContentPadding))

    AetherProfileEnabledCard(
      checked = prof?.enabled ?: false,
      onCheckedChange = { v -> actions.setProfileEnabled("aether", profile, v) },
    )

    AetherProfileTabs(
      selected = tab,
      onSelect = { tab = it },
    )

    when (tab) {
      0 -> AppListPickerCard(
        title = stringResource(R.string.apps_common_title),
        desc = stringResource(R.string.apps_common_desc),
        path = "$basePath/apps/user",
        actions = actions,
        snackHost = snackHost,
        programs = programs,
      )
      1 -> AetherSectionCard(
        title = "Aether Engine & DPI Bypass",
        desc = "Настройки движка Aether: выбор протокола (HTTP/2, MASQUE/HTTP/3, WireGuard), маскировка TLS Noise (--noize) и сканирование Cloudflare эндпоинтов (--scan).",
        accent = Color(0xFF00E676),
        icon = { Icon(Icons.Filled.Shield, contentDescription = null, modifier = Modifier.size(21.dp)) },
      ) {
          Text("Протокол передачи (--h2 / --masque / --wireguard / --mim / --gool)", style = MaterialTheme.typography.labelLarge)
          Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            val protos = listOf("h2", "masque", "wireguard", "mim", "gool")
            protos.forEach { p ->
              AetherOptionButton(
                text = p,
                selected = protocolText == p,
                enabled = loaded && !saving,
                onClick = { protocolText = p },
                modifier = Modifier.weight(1f),
              )
            }
          }

          Spacer(Modifier.height(4.dp))
          Text("TLS Noise / Фрагментация ClientHello (--noize)", style = MaterialTheme.typography.labelLarge)
          Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            val noizes = listOf("firewall", "tls", "none")
            noizes.forEach { n ->
              AetherOptionButton(
                text = n,
                selected = noizeText == n,
                enabled = loaded && !saving,
                onClick = { noizeText = n },
                modifier = Modifier.weight(1f),
              )
            }
          }

          Spacer(Modifier.height(4.dp))
          Text("Сканирование эндпоинтов Cloudflare (--scan)", style = MaterialTheme.typography.labelLarge)
          Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            val scans = listOf("balanced", "turbo", "off")
            scans.forEach { s ->
              AetherOptionButton(
                text = s,
                selected = scanModeText == s,
                enabled = loaded && !saving,
                onClick = { scanModeText = s },
                modifier = Modifier.weight(1f),
              )
            }
          }

          Spacer(Modifier.height(4.dp))
          Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
          ) {
            Column(Modifier.weight(1f)) {
              Text("Встроенный Tor (--tor)", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
              Text("Маршрутизация трафика через Tor внутри туннеля", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
            }
            Switch(checked = enableTorState, onCheckedChange = { enableTorState = it }, enabled = loaded && !saving)
          }

          Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
          ) {
            Column(Modifier.weight(1f)) {
              Text("Пометка сокетов (--mark 0xff)", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
              Text("Исключение сокетов Aether из TUN для предотвращения петли маршрутизации", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
            }
            Switch(checked = enableMarkState, onCheckedChange = { enableMarkState = it }, enabled = loaded && !saving)
          }

          OutlinedTextField(
            value = customArgsText,
            onValueChange = { customArgsText = it },
            label = { Text("Дополнительные флаги CLI (custom_args)") },
            singleLine = true,
            enabled = loaded && !saving,
            modifier = Modifier.fillMaxWidth(),
          )

          AetherSaveButton(
            dirty = settingsDirty,
            enabled = loaded && !saving && settingsDirty,
            saving = saving,
            onClick = { saveSettings() },
          )
      }
      2 -> AetherSectionCard(
        title = "Настройки tun2proxy и Сети",
        desc = "SOCKS5 port — общий локальный порт между Aether и tun2proxy. Виртуальный TUN-интерфейс и CIDR назначаются автоматически.",
        accent = Color(0xFF38BDF8),
        icon = { Icon(Icons.Filled.Settings, contentDescription = null, modifier = Modifier.size(21.dp)) },
      ) {
          OutlinedTextField(value = tunText, onValueChange = { tunText = it }, label = { Text("TUN interface") }, singleLine = true, enabled = loaded && !saving, modifier = Modifier.fillMaxWidth())
          OutlinedTextField(value = socksText, onValueChange = { socksText = it.filter { ch -> ch.isDigit() }.take(5) }, label = { Text("SOCKS5 backend port") }, singleLine = true, enabled = loaded && !saving, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), modifier = Modifier.fillMaxWidth())
          OutlinedTextField(value = mtuText, onValueChange = { mtuText = it.filter { ch -> ch.isDigit() }.take(4) }, label = { Text("MTU, optional 1280–9000") }, singleLine = true, enabled = loaded && !saving, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), modifier = Modifier.fillMaxWidth())
          OutlinedTextField(value = t2pLogText, onValueChange = { t2pLogText = it }, label = { Text("tun2proxy log level") }, singleLine = true, enabled = loaded && !saving, modifier = Modifier.fillMaxWidth())
          OutlinedTextField(value = aetherLogText, onValueChange = { aetherLogText = it }, label = { Text("Aether log level") }, singleLine = true, enabled = loaded && !saving, modifier = Modifier.fillMaxWidth())
          AetherSaveButton(
            dirty = settingsDirty,
            enabled = loaded && !saving && settingsDirty,
            saving = saving,
            onClick = { saveSettings() },
          )
      }
    }

    Spacer(Modifier.height(effectiveBottomContentPadding))
  }
}

@Composable
private fun AetherSectionCard(
  title: String,
  desc: String? = null,
  accent: Color = Color(0xFF00E676),
  icon: (@Composable () -> Unit)? = null,
  trailing: (@Composable () -> Unit)? = null,
  content: (@Composable ColumnScope.() -> Unit)? = null,
) {
  val compact = rememberIsCompactWidth()
  val shape = RoundedCornerShape(if (compact) 20.dp else 24.dp)
  Surface(
    modifier = Modifier.fillMaxWidth(),
    shape = shape,
    color = MaterialTheme.colorScheme.surface.copy(alpha = 0.64f),
    contentColor = MaterialTheme.colorScheme.onSurface,
    border = BorderStroke(1.dp, accent.copy(alpha = 0.34f)),
    tonalElevation = 0.dp,
    shadowElevation = 0.dp,
  ) {
    Box(
      modifier = Modifier
        .fillMaxWidth()
        .background(
          Brush.linearGradient(
            listOf(
              accent.copy(alpha = 0.13f),
              MaterialTheme.colorScheme.surface.copy(alpha = 0.05f),
              Color.Transparent,
            )
          ),
          shape = shape,
        )
        .padding(if (compact) 12.dp else 14.dp),
    ) {
      Column(verticalArrangement = Arrangement.spacedBy(if (compact) 10.dp else 12.dp)) {
        Row(
          modifier = Modifier.fillMaxWidth(),
          verticalAlignment = Alignment.CenterVertically,
          horizontalArrangement = Arrangement.spacedBy(if (compact) 10.dp else 12.dp),
        ) {
          if (icon != null) {
            Surface(
              modifier = Modifier.size(if (compact) 42.dp else 46.dp),
              shape = CircleShape,
              color = accent.copy(alpha = 0.16f),
              contentColor = accent,
              border = BorderStroke(1.dp, accent.copy(alpha = 0.38f)),
            ) {
              Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { icon() }
            }
          }
          Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Text(
              title,
              style = MaterialTheme.typography.titleSmall,
              fontWeight = FontWeight.Bold,
              color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.93f),
              maxLines = 1,
              overflow = TextOverflow.Ellipsis,
            )
            if (desc != null) {
              Text(
                desc,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.62f),
                maxLines = 3,
                overflow = TextOverflow.Ellipsis,
              )
            }
          }
          if (trailing != null) trailing()
        }
        if (content != null) content()
      }
    }
  }
}

@Composable
private fun AetherProfileEnabledCard(
  checked: Boolean,
  onCheckedChange: (Boolean) -> Unit,
) {
  val accent = if (checked) Color(0xFF22C55E) else Color(0xFFEF4444)
  AetherSectionCard(
    title = stringResource(R.string.enabled_card_profile_title),
    desc = stringResource(R.string.enabled_card_apply_hint),
    accent = accent,
    icon = { Icon(Icons.Filled.Extension, contentDescription = null, modifier = Modifier.size(22.dp)) },
    trailing = { Switch(checked = checked, onCheckedChange = onCheckedChange) },
  ) {
    Surface(
      shape = RoundedCornerShape(100.dp),
      color = accent.copy(alpha = 0.16f),
      contentColor = accent,
      border = BorderStroke(1.dp, accent.copy(alpha = 0.30f)),
    ) {
      Text(
        text = stringResource(if (checked) R.string.enabled_state_on else R.string.enabled_state_off),
        modifier = Modifier.padding(horizontal = 11.dp, vertical = 5.dp),
        style = MaterialTheme.typography.labelMedium,
        fontWeight = FontWeight.Bold,
        maxLines = 1,
      )
    }
  }
}

@Composable
private fun AetherProfileTabs(
  selected: Int,
  onSelect: (Int) -> Unit,
) {
  val compact = rememberIsCompactWidth()
  val tabs = listOf(
    0 to "Приложения",
    1 to "Aether Engine",
    2 to "Сеть & TUN",
  )
  Surface(
    shape = RoundedCornerShape(20.dp),
    color = MaterialTheme.colorScheme.surface.copy(alpha = 0.62f),
    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.14f)),
  ) {
    Row(
      modifier = Modifier.fillMaxWidth().padding(5.dp),
      horizontalArrangement = Arrangement.spacedBy(5.dp),
      verticalAlignment = Alignment.CenterVertically,
    ) {
      tabs.forEach { (index, label) ->
        val active = selected == index
        Surface(
          modifier = Modifier
            .weight(1f)
            .clickable { onSelect(index) },
          shape = RoundedCornerShape(16.dp),
          color = if (active) Color(0xFF00E676).copy(alpha = 0.18f) else Color.Transparent,
          contentColor = if (active) Color(0xFF69F0AE) else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.70f),
          border = if (active) BorderStroke(1.dp, Color(0xFF00E676).copy(alpha = 0.28f)) else null,
        ) {
          Box(
            modifier = Modifier.padding(horizontal = 6.dp, vertical = if (compact) 8.dp else 9.dp),
            contentAlignment = Alignment.Center,
          ) {
            Text(
              label,
              style = MaterialTheme.typography.labelMedium,
              fontWeight = if (active) FontWeight.Bold else FontWeight.SemiBold,
              maxLines = 1,
              overflow = TextOverflow.Ellipsis,
            )
          }
        }
      }
    }
  }
}

@Composable
private fun AetherSaveButton(
  dirty: Boolean,
  enabled: Boolean,
  saving: Boolean,
  onClick: () -> Unit,
) {
  val container by animateColorAsState(
    targetValue = if (dirty) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant,
    label = "aetherSaveContainer",
  )
  val content by animateColorAsState(
    targetValue = if (dirty) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurfaceVariant,
    label = "aetherSaveContent",
  )
  Button(
    onClick = onClick,
    enabled = enabled,
    modifier = Modifier.fillMaxWidth(),
    colors = ButtonDefaults.buttonColors(
      containerColor = container,
      contentColor = content,
      disabledContainerColor = container,
      disabledContentColor = content.copy(alpha = 0.72f),
    ),
  ) {
    Text(if (saving) stringResource(R.string.common_ellipsis) else stringResource(R.string.common_save))
  }
}

@Composable
private fun AetherOptionButton(
  text: String,
  selected: Boolean,
  enabled: Boolean,
  onClick: () -> Unit,
  modifier: Modifier = Modifier,
) {
  val container by animateColorAsState(
    targetValue = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant,
    label = "aetherOptionContainer",
  )
  val content by animateColorAsState(
    targetValue = if (selected) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurfaceVariant,
    label = "aetherOptionContent",
  )
  Button(
    onClick = onClick,
    enabled = enabled,
    modifier = modifier,
    contentPadding = PaddingValues(horizontal = 4.dp, vertical = 6.dp),
    colors = ButtonDefaults.buttonColors(
      containerColor = container,
      contentColor = content,
      disabledContainerColor = container.copy(alpha = 0.62f),
      disabledContentColor = content.copy(alpha = 0.62f),
    ),
  ) {
    Text(
      text = text,
      style = MaterialTheme.typography.labelSmall,
      maxLines = 1,
      overflow = TextOverflow.Ellipsis,
    )
  }
}
