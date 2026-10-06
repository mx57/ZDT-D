use anyhow::{bail, Context, Result};
use super::common::*;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use crate::{
    android::pkg_uid,
    shell::{self, Capture},
    vpn_netd::VpnNetdProfile,
    vpn_tether::VpnTetherProfile,
};

const AETHER_BIN: &str = "/data/adb/modules/ZDT-D/bin/aether";
const TUN2PROXY_BIN: &str = "/data/adb/modules/ZDT-D/bin/tun2socks";
const AETHER_ROOT: &str = "/data/adb/modules/ZDT-D/working_folder/aether";
const AETHER_PROFILE_ROOT: &str = "/data/adb/modules/ZDT-D/working_folder/aether/profile";
const ACTIVE_JSON: &str = "/data/adb/modules/ZDT-D/working_folder/aether/active.json";
const NETID_BASE: u32 = NETID_AETHER.0;
const NETID_MAX: u32 = NETID_AETHER.1;

fn all_netd_profile_names() -> Vec<String> {
    read_active().map(|a| a.profiles.keys().cloned().collect()).unwrap_or_default()
}

fn stable_netid_for(profile: &str) -> Result<u32> {
    stable_netid(NETID_BASE, NETID_MAX, &all_netd_profile_names(), profile)
}

const AETHER_NET_BASE: u32 = 0xAC1F_FD00; // 172.31.253.0
const TUN_WAIT: Duration = Duration::from_secs(18);
const PORT_WAIT: Duration = Duration::from_secs(25);

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ProfileState {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ActiveProfiles {
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileState>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProfileSetting {
    pub tun: String,
    #[serde(default = "default_socks5_port")]
    pub socks5_port: u16,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default = "default_noize")]
    pub noize: String,
    #[serde(default = "default_scan_mode")]
    pub scan_mode: String,
    #[serde(default)]
    pub enable_tor: bool,
    #[serde(default = "default_enable_mark")]
    pub enable_mark: bool,
    #[serde(default)]
    pub custom_args: String,
    #[serde(default)]
    pub mtu: Option<u16>,
    #[serde(default = "default_tun2proxy_loglevel")]
    pub tun2proxy_loglevel: String,
    #[serde(default = "default_aether_loglevel")]
    pub aether_loglevel: String,
}

fn default_socks5_port() -> u16 { 2090 }
fn default_protocol() -> String { "h2".to_string() }
fn default_noize() -> String { "firewall".to_string() }
fn default_scan_mode() -> String { "balanced".to_string() }
fn default_enable_mark() -> bool { true }
fn default_tun2proxy_loglevel() -> String { "info".to_string() }
fn default_aether_loglevel() -> String { "info".to_string() }

impl Default for ProfileSetting {
    fn default() -> Self {
        Self {
            tun: "aetun0".to_string(),
            socks5_port: default_socks5_port(),
            protocol: default_protocol(),
            noize: default_noize(),
            scan_mode: default_scan_mode(),
            enable_tor: false,
            enable_mark: default_enable_mark(),
            custom_args: String::new(),
            mtu: None,
            tun2proxy_loglevel: default_tun2proxy_loglevel(),
            aether_loglevel: default_aether_loglevel(),
        }
    }
}

#[derive(Debug, Clone)]
struct ProfilePlan {
    name: String,
    setting: ProfileSetting,
    profile_dir: PathBuf,
    app_in: PathBuf,
    app_out: PathBuf,
    aether_log_path: PathBuf,
    tun2proxy_log_path: PathBuf,
    requires_netd: bool,
    requires_tun: bool,
    netid: u32,
    tun_addr: String,
    cidr: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppSelection {
    Empty,
    MarkerOnly,
    RealApps,
}

pub fn root_path() -> PathBuf { PathBuf::from(AETHER_ROOT) }
pub fn active_path() -> PathBuf { PathBuf::from(ACTIVE_JSON) }
pub fn profiles_root() -> PathBuf { PathBuf::from(AETHER_PROFILE_ROOT) }
pub fn profile_root(profile: &str) -> PathBuf { profiles_root().join(profile) }

pub fn is_valid_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 10
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

pub fn ensure_valid_profile_name(name: &str) -> Result<()> {
    if !is_valid_profile_name(name) {
        bail!("aether profile name must be 1..10 chars and contain only English letters/digits/_/-");
    }
    Ok(())
}

pub fn ensure_profile_layout(profile: &str) -> Result<()> {
    ensure_valid_profile_name(profile)?;
    let root = profile_root(profile);
    fs::create_dir_all(root.join("app/uid"))?;
    fs::create_dir_all(root.join("app/out"))?;
    fs::create_dir_all(root.join("log"))?;
    ensure_file_empty(&root.join("app/uid/user_program"))?;
    ensure_file_empty(&root.join("app/out/user_program"))?;
    let setting_path = root.join("setting.json");
    if !setting_path.exists() {
        write_json_pretty(&setting_path, &default_setting_for_profile(profile))?;
    }
    Ok(())
}

pub fn ensure_root_layout() -> Result<()> {
    fs::create_dir_all(AETHER_PROFILE_ROOT)?;
    let active_path = active_path();
    if !active_path.exists() {
        write_json_pretty(&active_path, &ActiveProfiles::default())?;
    }
    Ok(())
}

pub fn read_active() -> Result<ActiveProfiles> {
    ensure_root_layout()?;
    read_json(&active_path())
}

pub fn write_active(active: &ActiveProfiles) -> Result<()> {
    ensure_root_layout()?;
    write_json_pretty(&active_path(), active)
}

pub fn read_setting(profile: &str) -> Result<ProfileSetting> {
    ensure_valid_profile_name(profile)?;
    read_json(&profile_root(profile).join("setting.json"))
}

pub fn write_setting(profile: &str, setting: &ProfileSetting) -> Result<()> {
    ensure_valid_profile_name(profile)?;
    validate_setting(setting)?;
    ensure_profile_layout(profile)?;
    write_json_pretty(&profile_root(profile).join("setting.json"), setting)
}

pub fn normalize_setting_value(value: Value) -> Result<ProfileSetting> {
    let setting: ProfileSetting = serde_json::from_value(value).context("bad aether setting.json")?;
    validate_setting(&setting)?;
    Ok(setting)
}

pub fn validate_setting(setting: &ProfileSetting) -> Result<()> {
    if !is_valid_ifname(&setting.tun) || is_forbidden_tun_name(&setting.tun) {
        bail!("tun must be 1..15 chars, must be a TUN name, and must not be a physical/system interface");
    }
    validate_local_port(setting.socks5_port, "socks5_port")?;
    if let Some(mtu) = setting.mtu {
        if !(1280..=9000).contains(&mtu) { bail!("mtu must be empty or 1280..9000"); }
    }
    validate_tun2proxy_loglevel(&setting.tun2proxy_loglevel)?;
    validate_protocol(&setting.protocol)?;
    validate_scan_mode(&setting.scan_mode)?;
    Ok(())
}

fn validate_local_port(port: u16, field: &str) -> Result<()> {
    if port < 1025 { bail!("{field} must be 1025..65535"); }
    Ok(())
}

fn validate_protocol(p: &str) -> Result<()> {
    match p.to_ascii_lowercase().as_str() {
        "h2" | "masque" | "h3" | "wireguard" | "mim" | "gool" | "" => Ok(()),
        _ => bail!("protocol must be h2/masque/wireguard/mim/gool"),
    }
}

fn validate_scan_mode(s: &str) -> Result<()> {
    match s.to_ascii_lowercase().as_str() {
        "turbo" | "balanced" | "off" | "" => Ok(()),
        _ => bail!("scan_mode must be turbo/balanced/off"),
    }
}

fn validate_tun2proxy_loglevel(v: &str) -> Result<()> {
    match v {
        "debug" | "info" | "warn" | "error" | "silent" => Ok(()),
        _ => bail!("tun2proxy_loglevel must be debug/info/warn/error/silent"),
    }
}

pub fn validate_enabled_tun_uniqueness_with_override(
    override_profile: Option<&str>,
    override_setting: Option<&ProfileSetting>,
    override_enabled: Option<bool>,
) -> Result<()> {
    ensure_root_layout()?;
    let active = read_active().unwrap_or_default();
    let mut seen: BTreeMap<String, String> = BTreeMap::new();

    for (name, st) in active.profiles {
        let enabled = if override_profile == Some(name.as_str()) {
            override_enabled.unwrap_or(st.enabled)
        } else {
            st.enabled
        };
        if !enabled { continue; }

        let setting = if override_profile == Some(name.as_str()) {
            override_setting.cloned().unwrap_or_else(|| read_setting(&name).unwrap_or_default())
        } else {
            read_setting(&name).unwrap_or_default()
        };
        validate_setting(&setting).with_context(|| format!("aether profile={name} setting validation"))?;
        if !app_list_requires_netd(&profile_root(&name).join("app/uid/user_program")) {
            continue;
        }

        if let Some(other) = seen.insert(setting.tun.clone(), name.clone()) {
            bail!("aether tun conflict: tun {} is used by enabled profiles {} and {}", setting.tun, other, name);
        }
    }
    Ok(())
}

pub fn enabled_tun_claims() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(active) = read_active() else { return out; };
    for (name, st) in active.profiles {
        if !st.enabled { continue; }
        let selected_for_hotspot = crate::settings::load_api_settings()
            .map(|st| st.hotspot_vpn_profile_for("aether") == Some(name.as_str()))
            .unwrap_or(false);
        if !selected_for_hotspot && !app_list_requires_netd(&profile_root(&name).join("app/uid/user_program")) { continue; }
        if let Ok(setting) = read_setting(&name) {
            out.push((format!("aether/{name}"), setting.tun));
        }
    }
    out
}

pub fn enabled_cidr_claims() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(active) = read_active() else { return out; };
    let hotspot_profile = crate::settings::load_api_settings()
        .ok()
        .and_then(|st| st.hotspot_vpn_profile_for("aether").map(|s| s.to_string()));
    let all_names: Vec<String> = active.profiles.keys().cloned().collect();
    for (name, st) in active.profiles {
        if !st.enabled { continue; }
        let Ok(setting) = read_setting(&name) else { continue; };
        if validate_setting(&setting).is_err() { continue; }
        let selected_for_hotspot = hotspot_profile.as_deref() == Some(name.as_str());
        if !selected_for_hotspot && !app_list_requires_netd(&profile_root(&name).join("app/uid/user_program")) { continue; }
        let Ok(netid) = stable_netid(NETID_BASE, NETID_MAX, &all_names, &name) else { continue; };
        if let Ok((_, cidr)) = generated_tun_addr_and_cidr(netid) {
            out.push((format!("aether/{name}"), cidr));
        }
    }
    out
}

fn app_selection(path: &Path) -> Result<AppSelection> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut has_marker = false;
    let mut has_real = false;
    for line in raw.lines() {
        let mut s = line.trim();
        if let Some((left, _)) = s.split_once('#') {
            s = left.trim();
        }
        if s.is_empty() {
            continue;
        }
        if pkg_uid::is_launch_marker_package(s) {
            has_marker = true;
        } else {
            has_real = true;
        }
    }
    Ok(if has_real {
        AppSelection::RealApps
    } else if has_marker {
        AppSelection::MarkerOnly
    } else {
        AppSelection::Empty
    })
}

fn app_list_requires_netd(path: &Path) -> bool {
    matches!(app_selection(path), Ok(AppSelection::RealApps))
}

pub fn suggest_free_socks5_port() -> u16 {
    let used_other = crate::ports::collect_used_ports_for_conflict_check().unwrap_or_default();
    let used_aether = collect_all_defined_aether_ports(None, None)
        .unwrap_or_default()
        .into_iter()
        .map(|(port, _)| port)
        .collect::<BTreeSet<u16>>();
    for port in 2090u16..=2199u16 {
        if !used_other.contains(&port) && !used_aether.contains(&port) { return port; }
    }
    default_socks5_port()
}

pub fn assign_free_ports_for_profile(profile: &str) -> Result<()> {
    ensure_valid_profile_name(profile)?;
    ensure_profile_layout(profile)?;
    let mut setting = read_setting(profile).unwrap_or_else(|_| default_setting_for_profile(profile));
    let used_other = crate::ports::collect_used_ports_for_conflict_check().unwrap_or_default();
    let own_prefix = format!("aether/{profile}/");
    let used = collect_all_defined_aether_ports(None, None)?
        .into_iter()
        .filter(|(_, label)| !label.starts_with(&own_prefix))
        .map(|(port, _)| port)
        .collect::<BTreeSet<u16>>();

    if setting.socks5_port < 1025 || used.contains(&setting.socks5_port) || used_other.contains(&setting.socks5_port) {
        for port in 2090u16..=2199u16 {
            if !used.contains(&port) && !used_other.contains(&port) {
                setting.socks5_port = port;
                break;
            }
        }
    }
    write_setting(profile, &setting)?;
    Ok(())
}

pub fn validate_port_uniqueness_with_override(
    override_profile: Option<&str>,
    override_setting: Option<&ProfileSetting>,
) -> Result<()> {
    let mut seen = BTreeMap::<u16, String>::new();
    for (port, label) in collect_all_defined_aether_ports(override_profile, override_setting)? {
        if let Some(other) = seen.insert(port, label.clone()) {
            bail!("aether port conflict: port {} is used by {} and {}", port, other, label);
        }
    }
    let used_other = crate::ports::collect_used_ports_for_conflict_check().unwrap_or_default();
    for (port, label) in collect_all_defined_aether_ports(override_profile, override_setting)? {
        if used_other.contains(&port) {
            bail!("aether port conflict: port {} used by {} conflicts with another ZDT-D local port", port, label);
        }
    }
    Ok(())
}

pub fn collect_all_defined_aether_ports(
    override_profile: Option<&str>,
    override_setting: Option<&ProfileSetting>,
) -> Result<Vec<(u16, String)>> {
    ensure_root_layout()?;
    let mut out = Vec::<(u16, String)>::new();
    let root = profiles_root();
    if let Ok(rd) = fs::read_dir(&root) {
        for ent in rd.flatten() {
            let profile_dir = ent.path();
            if !profile_dir.is_dir() { continue; }
            let Some(name) = profile_dir.file_name().and_then(|s| s.to_str()) else { continue; };
            if name.starts_with('.') { continue; }
            ensure_valid_profile_name(name)?;
            let setting = if override_profile == Some(name) {
                override_setting.cloned().unwrap_or_else(|| read_setting(name).unwrap_or_default())
            } else {
                read_setting(name).unwrap_or_default()
            };
            if setting.socks5_port != 0 { out.push((setting.socks5_port, format!("aether/{name}/socks5_port"))); }
        }
    }
    if let Some(name) = override_profile {
        let profile_dir = profile_root(name);
        if !profile_dir.exists() {
            let setting = override_setting.cloned().unwrap_or_else(|| default_setting_for_profile(name));
            if setting.socks5_port != 0 { out.push((setting.socks5_port, format!("aether/{name}/socks5_port"))); }
        }
    }
    Ok(out)
}

pub fn enabled_local_ports() -> Vec<u16> {
    let mut out = Vec::new();
    let Ok(active) = read_active() else { return out; };
    for (name, st) in active.profiles {
        if !st.enabled { continue; }
        if let Ok(setting) = read_setting(&name) {
            if setting.socks5_port != 0 { out.push(setting.socks5_port); }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

pub fn validate_start_plan() -> Result<()> {
    ensure_root_layout()?;
    let active = read_active().unwrap_or_default();
    let enabled_names: Vec<String> = active.profiles.iter()
        .filter(|(_, st)| st.enabled)
        .map(|(name, _)| name.clone())
        .collect();
    if enabled_names.is_empty() { return Ok(()); }

    let mut errors = Vec::<String>::new();
    if !Path::new(AETHER_BIN).is_file() { errors.push(format!("binary missing: {AETHER_BIN}")); }
    let tun2proxy_available = Path::new(TUN2PROXY_BIN).is_file();

    let mut seen_tuns = BTreeMap::<String, String>::new();
    let mut seen_ports = BTreeMap::<u16, String>::new();
    let used_ports = crate::ports::collect_used_ports_for_conflict_check().unwrap_or_default();

    for name in enabled_names {
        let profile_res: Result<()> = (|| {
            ensure_valid_profile_name(&name)?;
            let profile_dir = profile_root(&name);
            let setting = read_setting(&name).with_context(|| format!("read setting for profile {name}"))?;
            validate_setting(&setting).with_context(|| format!("validate setting for profile {name}"))?;
            let app_in = profile_dir.join("app/uid/user_program");
            let selection = app_selection(&app_in)?;
            let selected_for_hotspot = crate::settings::load_api_settings()
                .map(|st| st.hotspot_vpn_profile_for("aether") == Some(name.as_str()))
                .unwrap_or(false);
            if selection == AppSelection::Empty && !selected_for_hotspot {
                bail!("app list is empty: {}", app_in.display());
            }
            let requires_tun = selection == AppSelection::RealApps || selected_for_hotspot;
            if requires_tun && !tun2proxy_available {
                bail!("binary missing: {TUN2PROXY_BIN}");
            }
            if requires_tun {
                if let Some(other) = seen_tuns.insert(setting.tun.clone(), name.clone()) {
                    bail!("tun {} is used by enabled profiles {} and {}", setting.tun, other, name);
                }
            }
            let port = setting.socks5_port;
            let label = format!("{name}/socks5_port");
            if let Some(other) = seen_ports.insert(port, label.clone()) {
                bail!("port {} is used by {} and {}", port, other, label);
            }
            if used_ports.contains(&port) { bail!("socks5_port {} conflicts with another ZDT-D local port", port); }
            Ok(())
        })();
        if let Err(e) = profile_res { errors.push(format!("{name}: {e:#}")); }
    }
    if errors.is_empty() { Ok(()) } else { bail!("aether start plan has issue(s): {}", errors.join("; ")) }
}

pub fn has_enabled_profiles() -> bool {
    read_active().map(|a| a.profiles.values().any(|st| st.enabled)).unwrap_or(false)
}

pub fn has_profiles_requiring_netd() -> bool {
    read_active()
        .map(|active| {
            active.profiles.into_iter().any(|(name, st)| {
                st.enabled && app_list_requires_netd(&profile_root(&name).join("app/uid/user_program"))
            })
        })
        .unwrap_or(false)
}

pub fn is_running() -> bool { !main_pids_exact().is_empty() }

pub fn start_profiles_for_netd() -> Result<Vec<VpnNetdProfile>> {
    ensure_root_layout()?;
    let active = read_active().unwrap_or_default();
    let enabled_names: Vec<String> = active.profiles.iter()
        .filter(|(_, st)| st.enabled)
        .map(|(name, _)| name.clone())
        .collect();
    if enabled_names.is_empty() {
        info!("aether: no enabled profiles");
        return Ok(Vec::new());
    }

    crate::logging::user_info("aether: запуск");

    if !Path::new(AETHER_BIN).is_file() {
        warn!("aether: binary not found: {AETHER_BIN} -> skip");
        crate::logging::user_warn("aether: ошибка запуска, запуск продолжен");
        return Ok(Vec::new());
    }
    let tun2proxy_available = Path::new(TUN2PROXY_BIN).is_file();

    let hotspot_vpn_profile = crate::settings::load_api_settings()
        .ok()
        .and_then(|st| st.hotspot_vpn_profile_for("aether").map(|name| name.to_string()));
    let mut plans = Vec::new();
    let mut used_netids = BTreeSet::<u32>::new();
    let mut had_error = false;
    for name in enabled_names {
        let force_tun = hotspot_vpn_profile.as_deref() == Some(name.as_str());
        match build_profile_plan(&name, &used_netids, force_tun) {
            Ok(plan) => {
                if plan.requires_tun {
                    used_netids.insert(plan.netid);
                }
                plans.push(plan);
            }
            Err(e) => {
                had_error = true;
                warn!("aether: profile '{name}' skip: {e:#}");
            }
        }
    }
    if plans.is_empty() {
        if had_error { crate::logging::user_warn("aether: ошибка запуска, запуск продолжен"); }
        return Ok(Vec::new());
    }
    if let Err(e) = validate_plan_conflicts(&plans) {
        warn!("aether: profile conflict: {e:#}");
        crate::logging::user_warn("aether: ошибка запуска, запуск продолжен");
        return Ok(Vec::new());
    }

    let mut profiles = Vec::new();
    for plan in &plans {
        let res: Result<Option<VpnNetdProfile>> = (|| {
            spawn_aether(plan)?;
            wait_tcp_port("127.0.0.1", plan.setting.socks5_port, PORT_WAIT)
                .with_context(|| format!("aether profile={} wait socks5_port={}", plan.name, plan.setting.socks5_port))?;
            if !plan.requires_tun {
                info!("aether: profile={} uses launch marker only; skipping tun2proxy/vpn_netd", plan.name);
                return Ok(None);
            }
            if !tun2proxy_available {
                bail!("tun2proxy binary not found: {TUN2PROXY_BIN}");
            }
            spawn_tun2proxy(plan)?;
            wait_tun_link(&plan.setting.tun, TUN_WAIT)
                .with_context(|| format!("aether profile={} wait tun={}", plan.name, plan.setting.tun))?;
            configure_tun_addr(&plan.setting.tun, &plan.tun_addr)
                .with_context(|| format!("aether profile={} configure tun={}", plan.name, plan.setting.tun))?;
            wait_tun_ready(&plan.setting.tun)
                .with_context(|| format!("aether profile={} wait IPv4 tun={}", plan.name, plan.setting.tun))?;
            info!("aether: tun ready profile={} tun={} cidr={}", plan.name, plan.setting.tun, plan.cidr);
            if !plan.requires_netd {
                return Ok(None);
            }
            Ok(Some(VpnNetdProfile {
                owner_program: "aether".to_string(),
                profile: plan.name.clone(),
                netid: plan.netid,
                tun: plan.setting.tun.clone(),
                cidr: plan.cidr.clone(),
                gateway: None,
                dns: vec!["8.8.8.8".to_string()],
                app_list_path: plan.app_in.clone(),
                app_out_path: plan.app_out.clone(),
                endpoint_escape_ips: Vec::new(),
            }))
        })();
        match res {
            Ok(Some(profile)) => profiles.push(profile),
            Ok(None) => {}
            Err(e) => {
                had_error = true;
                warn!("aether: profile '{}' failed, startup continues: {e:#}", plan.name);
            }
        }
    }
    if had_error { crate::logging::user_warn("aether: часть профилей не запущена, запуск продолжен"); }
    info!("aether: prepared vpn_netd profiles count={}", profiles.len());
    Ok(profiles)
}

pub fn start_construction_profile(profile: &str) -> Result<()> {
    ensure_root_layout()?;
    ensure_valid_profile_name(profile)?;
    let active = read_active().unwrap_or_default();
    if !active.profiles.get(profile).map(|st| st.enabled).unwrap_or(false) {
        info!("aether: construction profile '{}' is disabled, skip targeted start", profile);
        return Ok(());
    }

    if !Path::new(AETHER_BIN).is_file() {
        warn!("aether: binary not found: {AETHER_BIN} -> skip targeted start");
        return Ok(());
    }
    let tun2proxy_available = Path::new(TUN2PROXY_BIN).is_file();
    let hotspot_vpn_profile = crate::settings::load_api_settings()
        .ok()
        .and_then(|st| st.hotspot_vpn_profile_for("aether").map(|name| name.to_string()));

    let mut used_netids = BTreeSet::<u32>::new();
    let mut plans = Vec::<ProfilePlan>::new();
    for (name, st) in active.profiles.iter() {
        if !st.enabled || name == profile {
            continue;
        }
        let force_tun = hotspot_vpn_profile.as_deref() == Some(name.as_str());
        match build_profile_plan(name, &used_netids, force_tun) {
            Ok(plan) => {
                if plan.requires_tun {
                    used_netids.insert(plan.netid);
                }
                plans.push(plan);
            }
            Err(e) => warn!(
                "aether: ignoring unrelated enabled profile '{}' during targeted construction start of '{}': {e:#}",
                name,
                profile
            ),
        }
    }

    let force_tun = hotspot_vpn_profile.as_deref() == Some(profile);
    let plan = build_profile_plan(profile, &used_netids, force_tun)
        .with_context(|| format!("aether targeted construction plan profile={profile}"))?;
    plans.push(plan.clone());
    validate_plan_conflicts(&plans)?;

    spawn_aether(&plan)?;
    wait_tcp_port("127.0.0.1", plan.setting.socks5_port, PORT_WAIT)
        .with_context(|| format!("aether targeted profile={} wait socks5_port={}", plan.name, plan.setting.socks5_port))?;
    if !plan.requires_tun {
        info!("aether: targeted profile={} uses launch marker only; skipping tun2proxy/vpn_netd", plan.name);
        return Ok(());
    }
    if !tun2proxy_available {
        bail!("tun2proxy binary not found: {TUN2PROXY_BIN}");
    }
    spawn_tun2proxy(&plan)?;
    wait_tun_link(&plan.setting.tun, TUN_WAIT)
        .with_context(|| format!("aether targeted profile={} wait tun={}", plan.name, plan.setting.tun))?;
    configure_tun_addr(&plan.setting.tun, &plan.tun_addr)
        .with_context(|| format!("aether targeted profile={} configure tun={}", plan.name, plan.setting.tun))?;
    wait_tun_ready(&plan.setting.tun)
        .with_context(|| format!("aether targeted profile={} wait IPv4 tun={}", plan.name, plan.setting.tun))?;
    info!("aether: targeted tun ready profile={} tun={} cidr={}", plan.name, plan.setting.tun, plan.cidr);
    if plan.requires_netd {
        crate::vpn_netd::start_profiles(vec![VpnNetdProfile {
            owner_program: "aether".to_string(),
            profile: plan.name.clone(),
            netid: plan.netid,
            tun: plan.setting.tun.clone(),
            cidr: plan.cidr.clone(),
            gateway: None,
            dns: vec!["8.8.8.8".to_string()],
            app_list_path: plan.app_in.clone(),
            app_out_path: plan.app_out.clone(),
            endpoint_escape_ips: Vec::new(),
        }])?;
    }
    Ok(())
}

pub fn start_profile_for_hotspot_vpn(profile: &str) -> Result<Option<VpnTetherProfile>> {
    ensure_root_layout()?;
    let active = read_active().unwrap_or_default();
    if !active.profiles.get(profile).map(|st| st.enabled).unwrap_or(false) {
        warn!("aether: hotspot VPN profile '{}' is not enabled", profile);
        return Ok(None);
    }
    if !Path::new(AETHER_BIN).is_file() {
        warn!("aether: binary not found: {AETHER_BIN} -> skip hotspot VPN");
        return Ok(None);
    }
    if !Path::new(TUN2PROXY_BIN).is_file() {
        warn!("aether: tun2proxy binary not found: {TUN2PROXY_BIN} -> skip hotspot VPN");
        return Ok(None);
    }
    let plan = build_profile_plan_for_hotspot(profile)?;
    info!("aether: hotspot VPN start profile={} tun={}", plan.name, plan.setting.tun);
    if wait_tun_ready(&plan.setting.tun).is_ok() {
        info!("aether: hotspot VPN reusing ready tun={}", plan.setting.tun);
    } else {
        spawn_aether(&plan)?;
        wait_tcp_port("127.0.0.1", plan.setting.socks5_port, PORT_WAIT)
            .with_context(|| format!("aether hotspot profile={} wait socks5_port={}", plan.name, plan.setting.socks5_port))?;
        spawn_tun2proxy(&plan)?;
        wait_tun_link(&plan.setting.tun, TUN_WAIT)
            .with_context(|| format!("aether hotspot profile={} wait tun={}", plan.name, plan.setting.tun))?;
        configure_tun_addr(&plan.setting.tun, &plan.tun_addr)
            .with_context(|| format!("aether hotspot profile={} configure tun={}", plan.name, plan.setting.tun))?;
        wait_tun_ready(&plan.setting.tun)
            .with_context(|| format!("aether hotspot profile={} wait IPv4 tun={}", plan.name, plan.setting.tun))?;
    }
    Ok(Some(VpnTetherProfile {
        owner_program: "aether".to_string(),
        profile: plan.name.clone(),
        tun: plan.setting.tun.clone(),
        cidr: plan.cidr.clone(),
        gateway: None,
        dns: vec!["8.8.8.8".to_string()],
    }))
}

fn build_profile_plan_for_hotspot(profile: &str) -> Result<ProfilePlan> {
    ensure_valid_profile_name(profile)?;
    let active = read_active().unwrap_or_default();
    let mut used_netids = BTreeSet::<u32>::new();
    for (name, st) in active.profiles.iter() {
        if !st.enabled { continue; }
        let is_target = name == profile;
        match build_profile_plan(name, &used_netids, is_target) {
            Ok(plan) => {
                if plan.requires_tun {
                    used_netids.insert(plan.netid);
                }
                if is_target {
                    return Ok(plan);
                }
            }
            Err(e) if is_target => return Err(e),
            Err(_) => continue,
        }
    }
    bail!("hotspot VPN profile is not enabled: {profile}")
}

fn build_profile_plan(profile: &str, used_netids: &BTreeSet<u32>, force_tun: bool) -> Result<ProfilePlan> {
    ensure_valid_profile_name(profile)?;
    ensure_profile_layout(profile)?;
    let profile_dir = profile_root(profile);
    let setting = read_setting(profile)?;
    validate_setting(&setting)?;

    let app_in = profile_dir.join("app/uid/user_program");
    let app_out = profile_dir.join("app/out/user_program");
    ensure_file_empty(&app_in)?;
    let selection = app_selection(&app_in)?;
    if selection == AppSelection::Empty && !force_tun {
        bail!("app list is empty: {}", app_in.display());
    }
    let requires_netd = selection == AppSelection::RealApps;
    let requires_tun = requires_netd || force_tun;

    let netid = if requires_tun {
        let id = stable_netid_for(profile)?;
        if used_netids.contains(&id) {
            bail!("netid {id} is already used by another aether profile");
        }
        id
    } else { 0 };
    let (tun_addr, cidr) = if requires_tun {
        generated_tun_addr_and_cidr(netid)?
    } else {
        (String::new(), String::new())
    };
    Ok(ProfilePlan {
        name: profile.to_string(),
        setting,
        profile_dir: profile_dir.clone(),
        app_in,
        app_out,
        aether_log_path: profile_dir.join("log/aether.log"),
        tun2proxy_log_path: profile_dir.join("log/tun2proxy.log"),
        requires_netd,
        requires_tun,
        netid,
        tun_addr,
        cidr,
    })
}

fn validate_plan_conflicts(plans: &[ProfilePlan]) -> Result<()> {
    let mut seen_tun: BTreeMap<String, String> = BTreeMap::new();
    let mut seen_port: BTreeMap<u16, String> = BTreeMap::new();
    let used_ports = crate::ports::collect_used_ports_for_conflict_check().unwrap_or_default();
    for plan in plans {
        if plan.requires_tun {
            if let Some(other) = seen_tun.insert(plan.setting.tun.clone(), plan.name.clone()) {
                bail!("aether tun conflict: tun {} is used by enabled profiles {} and {}", plan.setting.tun, other, plan.name);
            }
        }
        let port = plan.setting.socks5_port;
        let label = format!("{}/socks5_port", plan.name);
        if let Some(other) = seen_port.insert(port, label.clone()) {
            bail!("aether port conflict: port {} is used by {} and {}", port, other, label);
        }
        if used_ports.contains(&port) { bail!("aether port conflict: socks5_port {} conflicts with another ZDT-D local port", port); }
    }
    Ok(())
}

fn spawn_aether(plan: &ProfilePlan) -> Result<()> {
    if aether_profile_process_running(plan.setting.socks5_port) {
        info!("aether: profile={} already running on socks5_port={}, skip spawn", plan.name, plan.setting.socks5_port);
        return Ok(());
    }
    fs::create_dir_all(plan.profile_dir.join("log"))?;
    let logf = OpenOptions::new().create(true).write(true).truncate(true).open(&plan.aether_log_path)
        .with_context(|| format!("open log {}", plan.aether_log_path.display()))?;
    let logf_err = logf.try_clone().context("clone aether log")?;

    let mut cmd = Command::new(AETHER_BIN);
    cmd.arg("--bind").arg(format!("127.0.0.1:{}", plan.setting.socks5_port));

    let proto = plan.setting.protocol.to_ascii_lowercase();
    match proto.as_str() {
        "h2" => { cmd.arg("--h2"); }
        "masque" | "h3" => { cmd.arg("--masque"); }
        "wireguard" => { cmd.arg("--wireguard"); }
        "mim" => { cmd.arg("--mim"); }
        "gool" => { cmd.arg("--gool"); }
        _ => {
            if !proto.is_empty() {
                cmd.arg(format!("--{proto}"));
            } else {
                cmd.arg("--h2");
            }
        }
    }

    if !plan.setting.noize.is_empty() && plan.setting.noize != "none" {
        cmd.arg("--noize").arg(&plan.setting.noize);
    }

    if !plan.setting.scan_mode.is_empty() && plan.setting.scan_mode != "off" {
        cmd.arg("--scan").arg(&plan.setting.scan_mode);
    }

    if plan.setting.enable_tor {
        cmd.arg("--tor");
    }

    if plan.setting.enable_mark {
        cmd.arg("--mark").arg("0xff");
    }

    if !plan.setting.custom_args.trim().is_empty() {
        let args = normalize_config_args(&plan.setting.custom_args);
        cmd.args(args);
    }

    cmd.current_dir(&plan.profile_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::from(logf))
        .stderr(Stdio::from(logf_err));
    unsafe { cmd.pre_exec(|| { let _ = libc::setsid(); Ok(()) }); }
    let child = cmd.spawn().with_context(|| format!("spawn {AETHER_BIN}"))?;
    info!("aether: spawned profile={} pid={} socks5_port={} log={}", plan.name, child.id(), plan.setting.socks5_port, plan.aether_log_path.display());
    thread::sleep(Duration::from_millis(400));
    let proc_path = PathBuf::from("/proc").join(child.id().to_string());
    if !proc_path.is_dir() {
        warn!("aether: profile={} pid={} exited quickly; check log {}", plan.name, child.id(), plan.aether_log_path.display());
    }
    Ok(())
}

fn spawn_tun2proxy(plan: &ProfilePlan) -> Result<()> {
    let proxy = format!("socks5://127.0.0.1:{}", plan.setting.socks5_port);
    if tun2proxy_profile_process_running(&plan.setting.tun, &proxy) {
        info!("aether: tun2proxy profile={} already running for tun={} proxy={}, skip spawn", plan.name, plan.setting.tun, proxy);
        return Ok(());
    }
    fs::create_dir_all(plan.profile_dir.join("log"))?;
    let logf = OpenOptions::new().create(true).write(true).truncate(true).open(&plan.tun2proxy_log_path)
        .with_context(|| format!("open log {}", plan.tun2proxy_log_path.display()))?;
    let logf_err = logf.try_clone().context("clone aether tun2proxy log")?;
    let mut cmd = Command::new(TUN2PROXY_BIN);
    cmd.arg("--device")
        .arg(format!("tun://{}", plan.setting.tun))
        .arg("--proxy")
        .arg(&proxy)
        .arg("--loglevel")
        .arg(&plan.setting.tun2proxy_loglevel);
    if let Some(mtu) = plan.setting.mtu {
        cmd.arg("--mtu").arg(mtu.to_string());
    }
    cmd.current_dir(&plan.profile_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::from(logf))
        .stderr(Stdio::from(logf_err));
    unsafe { cmd.pre_exec(|| { let _ = libc::setsid(); Ok(()) }); }
    let child = cmd.spawn().with_context(|| format!("spawn {TUN2PROXY_BIN} for aether"))?;
    info!("aether: spawned tun2proxy profile={} pid={} tun={} proxy={} log={}", plan.name, child.id(), plan.setting.tun, proxy, plan.tun2proxy_log_path.display());
    Ok(())
}

fn aether_profile_process_running(socks5_port: u16) -> bool {
    let pattern = format!("--bind 127.0.0.1:{socks5_port}");
    let cmd = format!(
        "ps -ef 2>/dev/null | grep -F {} | grep -F 'aether' | grep -v grep >/dev/null 2>&1",
        shell_quote_for_sh(&pattern)
    );
    shell::ok_sh(&cmd).is_ok()
}

fn tun2proxy_profile_process_running(tun: &str, proxy: &str) -> bool {
    let pattern = format!("{} --device tun://{} --proxy {}", TUN2PROXY_BIN, tun, proxy);
    let cmd = format!("ps -ef 2>/dev/null | grep -F {} | grep -v grep >/dev/null 2>&1", shell_quote_for_sh(&pattern));
    shell::ok_sh(&cmd).is_ok()
}

fn wait_tun_ready(tun: &str) -> Result<()> {
    let start = Instant::now();
    loop {
        if start.elapsed() >= TUN_WAIT { bail!("tun {tun} is not ready after {:?}", TUN_WAIT); }
        let (code, out) = shell::run_timeout("ip", &["-o", "-4", "addr", "show", "dev", tun], Capture::Stdout, IP_TIMEOUT).unwrap_or((1, String::new()));
        if code == 0 && out.lines().any(|l| l.contains(" inet ") || l.split_whitespace().any(|t| t == "inet")) { return Ok(()); }
        thread::sleep(Duration::from_millis(300));
    }
}

fn generated_tun_addr_and_cidr(netid: u32) -> Result<(String, String)> {
    if !(NETID_BASE..=NETID_MAX).contains(&netid) { bail!("aether netid out of generated range: {netid}"); }
    let offset = (netid - NETID_BASE) * 4;
    let network = AETHER_NET_BASE.checked_add(offset).ok_or_else(|| anyhow::anyhow!("aether cidr overflow"))?;
    let addr = network + 1;
    Ok((format!("{}/30", u32_to_ipv4(addr)), format!("{}/30", u32_to_ipv4(network))))
}

fn is_forbidden_tun_name(s: &str) -> bool {
    s == "lo" || s == "dummy0" || s.starts_with("wlan") || s.starts_with("rmnet") || s.starts_with("ccmni") || s.starts_with("eth") || s.starts_with("ap") || s.starts_with("rndis")
}

fn ensure_file_empty(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
    if !path.exists() { fs::write(path, "")?; }
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    crate::jsonfs::read_json_short_ctx(path)
}

fn write_json_pretty<T: Serialize>(path: &Path, v: &T) -> Result<()> {
    if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
    let txt = serde_json::to_string_pretty(v)?;
    write_text_atomic(path, &txt)
}

fn write_text_atomic(path: &Path, txt: &str) -> Result<()> {
    if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, txt)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn main_pids_exact() -> Vec<i32> {
    let mut pids = Vec::new();
    let cmd = r#"sh -c "pgrep -f '^/data/adb/modules/ZDT-D/bin/aether .*' 2>/dev/null || true""#;
    if let Ok(out) = shell::capture_quiet(cmd) { pids.extend(parse_pid_lines(&out)); }
    if pids.is_empty() {
        let ps_cmd = r#"sh -c "ps -ef 2>/dev/null | grep -F '/data/adb/modules/ZDT-D/bin/aether' | grep -v grep || true""#;
        if let Ok(out) = shell::capture_quiet(ps_cmd) {
            for line in out.lines() {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() > 1 {
                    if let Ok(pid) = cols[1].parse::<i32>() { if pid > 1 { pids.push(pid); } }
                }
            }
        }
    }
    pids.sort_unstable();
    pids.dedup();
    pids
}

pub fn tun2proxy_pids_exact() -> Vec<i32> {
    let mut pids = Vec::new();
    let cmd = r#"sh -c "pgrep -f '^/data/adb/modules/ZDT-D/bin/tun2socks --device tun://aetun.* --proxy socks5://127\.0\.0\.1:[0-9]+.*$' 2>/dev/null || true""#;
    if let Ok(out) = shell::capture_quiet(cmd) { pids.extend(parse_pid_lines(&out)); }
    pids.sort_unstable();
    pids.dedup();
    pids
}

fn default_setting_for_profile(profile: &str) -> ProfileSetting {
    let mut s = ProfileSetting::default();
    let idx = profile_index(profile).unwrap_or(0);
    s.tun = format!("aetun{}", idx);
    s
}

fn profile_index(profile: &str) -> Option<u32> {
    let digits = profile.strip_prefix("profile")?;
    digits.parse::<u32>().ok().map(|n| n.saturating_sub(1))
}
