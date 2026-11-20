//! `seuil doctor`: read-only diagnostics for every runtime dependency.
//!
//! [FR-001|NFR-005] The blocking set is BlueZ reachability, adapter power, the
//! PipeWire socket, the credential store, and an observed CoC PSM. The advisory
//! set is the bluetoothd experimental flag, the user unit state, and SteamOS
//! detection. Each check prints one line and no probe aborts the run: a missing
//! tool or an unreachable bus becomes a line, not an error.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use bluer::{Adapter, AddressType};
use tokio::time::timeout;

use crate::auth::Credentials;
use crate::{auth, ble, config, Cli};

/// Upper bound on one probe that talks to D-Bus, BlueZ, or a helper tool.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Upper bound on the CoC connect probe. The L2CAP layer carries its own 10 s
/// timeout; doctor caps it lower so the whole run stays under 10 s.
const COC_TIMEOUT: Duration = Duration::from_secs(8);

/// PSM reported when the advertisement carries none. It is a reference value,
/// not a requirement: doctor reports the observed PSM and never asserts this.
const DEFAULT_PSM: u16 = ble::DEFAULT_COC;

/// Credential key file name, checked before `Credentials::load` so a missing
/// key is reported instead of silently regenerated.
const KEY_FILE: &str = "credentials.key";

/// Systemd user unit name.
const SERVICE: &str = "seuil.service";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Pass,
    Info,
    Warn,
    Fail,
}

/// One diagnostic line. Blocking lines can fail and set the exit code;
/// advisory lines only report.
struct CheckLine {
    blocking: bool,
    name: &'static str,
    status: Status,
    detail: String,
}

impl CheckLine {
    fn new(name: &'static str, blocking: bool, status: Status, detail: String) -> Self {
        Self {
            blocking,
            name,
            status,
            detail,
        }
    }

    fn pass(name: &'static str, detail: String) -> Self {
        Self::new(name, true, Status::Pass, detail)
    }

    fn fail(name: &'static str, detail: String) -> Self {
        Self::new(name, true, Status::Fail, detail)
    }

    fn info(name: &'static str, detail: String) -> Self {
        Self::new(name, false, Status::Info, detail)
    }

    fn warn(name: &'static str, detail: String) -> Self {
        Self::new(name, false, Status::Warn, detail)
    }

    fn tag(&self) -> &'static str {
        match self.status {
            Status::Pass => "pass",
            Status::Info => "info",
            Status::Warn => "warn",
            Status::Fail => "fail",
        }
    }
}

/// Runs the checks and returns the process exit code.
///
/// 0 when every blocking check passes, 1 when a blocking check fails, 2 when
/// the check runner itself fails.
pub async fn run(cli: &Cli) -> i32 {
    match render(cli).await {
        Ok(failed) => {
            if failed {
                1
            } else {
                0
            }
        }
        Err(error) => {
            eprintln!("fail  doctor          internal error: {error:#}");
            2
        }
    }
}

/// Collects and prints the checks; returns whether a blocking check failed.
async fn render(cli: &Cli) -> Result<bool> {
    let lines = collect(cli).await?;
    let failed = lines
        .iter()
        .any(|line| line.blocking && line.status == Status::Fail);

    let mut out = std::io::stdout().lock();
    for line in &lines {
        writeln!(out, "{:<4}  {:<14}  {}", line.tag(), line.name, line.detail)?;
    }
    out.flush()?;
    Ok(failed)
}

async fn collect(cli: &Cli) -> Result<Vec<CheckLine>> {
    let (bluez_line, adapter) = probe_bluez(cli).await;
    let mut lines = Vec::with_capacity(8);
    lines.push(bluez_line);
    lines.push(probe_adapter(cli, adapter.as_ref()).await);
    lines.push(probe_pipewire());
    lines.push(probe_credentials());
    lines.push(probe_psm(cli, adapter.as_ref()).await);
    lines.push(probe_experimental());
    lines.push(probe_user_unit().await);
    lines.push(probe_steamos());
    Ok(lines)
}

/// Checks the system bus and reports whether the adapter is present.
async fn probe_bluez(cli: &Cli) -> (CheckLine, Option<Adapter>) {
    let session = match timeout(PROBE_TIMEOUT, bluer::Session::new()).await {
        Ok(Ok(session)) => session,
        Ok(Err(error)) => {
            return (
                CheckLine::fail(
                    "bluez",
                    format!(
                        "org.bluez is not reachable on the system bus: {error}; start it: \
                         sudo systemctl start bluetooth"
                    ),
                ),
                None,
            );
        }
        Err(_) => {
            return (
                CheckLine::fail(
                    "bluez",
                    format!(
                        "no system-bus answer within {PROBE_TIMEOUT:?}; restart bluetoothd: \
                         sudo systemctl restart bluetooth"
                    ),
                ),
                None,
            );
        }
    };

    match session.adapter(&cli.adapter) {
        Ok(adapter) => (
            CheckLine::pass("bluez", "org.bluez is reachable on the system bus".into()),
            Some(adapter),
        ),
        Err(error) => (
            CheckLine::fail(
                "bluez",
                format!(
                    "org.bluez is reachable but adapter {} is missing ({error}); pass --adapter",
                    cli.adapter
                ),
            ),
            None,
        ),
    }
}

/// Checks that the configured adapter exists and is powered.
async fn probe_adapter(cli: &Cli, adapter: Option<&Adapter>) -> CheckLine {
    let Some(adapter) = adapter else {
        return CheckLine::fail(
            "adapter",
            format!(
                "{} could not be checked because BlueZ is unreachable; fix the bluez line \
                 first (start bluetoothd: sudo systemctl start bluetooth)",
                cli.adapter
            ),
        );
    };
    match timeout(PROBE_TIMEOUT, adapter.is_powered()).await {
        Ok(Ok(true)) => CheckLine::pass("adapter", format!("{} is powered on", cli.adapter)),
        Ok(Ok(false)) => CheckLine::fail(
            "adapter",
            format!("{} is powered off; run `bluetoothctl power on`", cli.adapter),
        ),
        Ok(Err(error)) => CheckLine::fail(
            "adapter",
            format!(
                "could not read Powered for {}: {error}; restart bluetoothd: \
                 sudo systemctl restart bluetooth",
                cli.adapter
            ),
        ),
        Err(_) => CheckLine::fail(
            "adapter",
            format!(
                "{} did not answer within {PROBE_TIMEOUT:?}; restart bluetoothd",
                cli.adapter
            ),
        ),
    }
}

/// Checks the PipeWire socket and reports the audio probe tools in the detail.
fn probe_pipewire() -> CheckLine {
    let tools = audio_tools_detail();
    let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") else {
        return CheckLine::fail(
            "pipewire",
            format!("XDG_RUNTIME_DIR is unset, so the PipeWire socket cannot be located; {tools}"),
        );
    };
    let socket = Path::new(&runtime).join("pipewire-0");
    if socket.exists() {
        CheckLine::pass(
            "pipewire",
            format!("socket {} present; {tools}", socket.display()),
        )
    } else {
        CheckLine::fail(
            "pipewire",
            format!(
                "socket {} is missing; start PipeWire in this user session; {tools}",
                socket.display()
            ),
        )
    }
}

fn audio_tools_detail() -> String {
    let pactl = if command_available("pactl") {
        "pactl present"
    } else {
        "pactl missing (PipeWire stream detection degraded)"
    };
    let playerctl = if command_available("playerctl") {
        "playerctl present"
    } else {
        "playerctl missing (MPRIS detection degraded)"
    };
    format!("{pactl}, {playerctl}")
}

/// Checks that both credential files exist and load.
fn probe_credentials() -> CheckLine {
    let path = auth::credentials_path();
    let key = path
        .parent()
        .map(|dir| dir.join(KEY_FILE))
        .unwrap_or_else(|| Path::new(KEY_FILE).to_path_buf());

    if !path.exists() {
        return CheckLine::fail(
            "credentials",
            format!(
                "{} is missing; run `seuil setup` in Desktop Mode",
                path.display()
            ),
        );
    }
    if !key.exists() {
        return CheckLine::fail(
            "credentials",
            format!(
                "{} is missing; re-enroll with `seuil setup --reauth` in Desktop Mode",
                key.display()
            ),
        );
    }

    match Credentials::load() {
        Ok(Some(credentials)) if !credentials.account_key.is_empty() => {
            CheckLine::pass("credentials", format!("loaded {}", path.display()))
        }
        Ok(_) => CheckLine::fail(
            "credentials",
            format!(
                "{} carries no account key; run `seuil setup` in Desktop Mode",
                path.display()
            ),
        ),
        Err(error) => CheckLine::fail(
            "credentials",
            format!(
                "{} could not be loaded: {error}; run `seuil setup --reauth` in Desktop Mode",
                path.display()
            ),
        ),
    }
}

/// Reports the PSM observed in the phone's advertisement and probes the CoC.
async fn probe_psm(cli: &Cli, adapter: Option<&Adapter>) -> CheckLine {
    let Some(adapter) = adapter else {
        return CheckLine::fail(
            "coc-psm",
            "not checked: no BlueZ adapter; fix the adapter check first (restart bluetoothd \
             or verify the adapter name)"
                .into(),
        );
    };
    let Some(phone) = phone_address(cli) else {
        return CheckLine::fail(
            "coc-psm",
            "no phone address; run `seuil setup` in Desktop Mode or pass --phone".into(),
        );
    };
    let address = match phone.parse::<bluer::Address>() {
        Ok(address) => address,
        Err(_) => {
            return CheckLine::fail(
                "coc-psm",
                format!(
                    "configured phone address {phone} is not a Bluetooth address; rerun `seuil setup`"
                ),
            );
        }
    };

    let keys = ble::scanning_keys(fingerprint(cli).as_deref());
    let observed = timeout(
        PROBE_TIMEOUT,
        ble::read_phone_coc_psm(adapter, &address, &keys),
    )
    .await;
    let psm = match observed {
        Ok(Some(psm)) => psm,
        Ok(None) => {
            return CheckLine::fail(
                "coc-psm",
                format!(
                    "no type-1 PSM in the latest advertisement from {phone}; keep the phone \
                     unlocked and the Continuity service running"
                ),
            );
        }
        Err(_) => {
            return CheckLine::fail(
                "coc-psm",
                format!(
                    "timed out after {PROBE_TIMEOUT:?} reading the advertisement from {phone}; \
                     keep the phone unlocked and near this machine"
                ),
            );
        }
    };

    let address_type = match adapter.device(address) {
        Ok(device) => timeout(PROBE_TIMEOUT, device.address_type())
            .await
            .ok()
            .and_then(|result| result.ok())
            .unwrap_or(AddressType::LePublic),
        Err(_) => AddressType::LePublic,
    };

    let connected = timeout(
        COC_TIMEOUT,
        ble::l2cap::connect_l2cap_coc(&phone, address_type, psm),
    )
    .await;
    match connected {
        Ok(Ok(channel)) => {
            drop(channel);
            CheckLine::pass(
                "coc-psm",
                format!(
                    "observed PSM {psm:#06x} (default constant {DEFAULT_PSM}); CoC connect succeeded"
                ),
            )
        }
        Ok(Err(error)) => CheckLine::fail(
            "coc-psm",
            format!(
                "observed PSM {psm:#06x} (default constant {DEFAULT_PSM}); CoC connect failed: {error:#}"
            ),
        ),
        Err(_) => CheckLine::fail(
            "coc-psm",
            format!(
                "observed PSM {psm:#06x} (default constant {DEFAULT_PSM}); CoC connect timed out after {COC_TIMEOUT:?}"
            ),
        ),
    }
}

/// Reports whether bluetoothd runs the experimental interfaces and whether the
/// optional drop-in is installed. Advisory only: the current code path scans
/// through `SetDiscoveryFilter`, and `LEAdvertisingManager1` is stable.
fn probe_experimental() -> CheckLine {
    let dropin = if Path::new(crate::setup::BLUEZ_DROPIN_PATH).exists() {
        "drop-in present"
    } else {
        "drop-in absent"
    };
    let sdp = if command_available("sdptool") {
        "sdptool present"
    } else {
        "sdptool missing, phone SDP check skipped"
    };
    match bluetoothd_experimental() {
        Some(true) => CheckLine::info(
            "experimental",
            format!(
                "{dropin}; {sdp}; bluetoothd runs with --experimental; not required for the current code path"
            ),
        ),
        Some(false) => CheckLine::info(
            "experimental",
            format!(
                "{dropin}; {sdp}; bluetoothd runs without --experimental; not required for the current code path"
            ),
        ),
        None => CheckLine::info(
            "experimental",
            format!(
                "{dropin}; {sdp}; bluetoothd command line not readable; the flag is not required for the current code path"
            ),
        ),
    }
}

fn bluetoothd_experimental() -> Option<bool> {
    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let Ok(raw) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let args: Vec<&[u8]> = raw
            .split(|byte| *byte == 0)
            .filter(|arg| !arg.is_empty())
            .collect();
        let Some(program) = args.first() else {
            continue;
        };
        if !program.ends_with(b"bluetoothd") {
            continue;
        }
        return Some(
            args[1..]
                .iter()
                .any(|arg| *arg == b"-E" || *arg == b"--experimental"),
        );
    }
    None
}

async fn probe_user_unit() -> CheckLine {
    if !command_available("systemctl") {
        return CheckLine::warn(
            "user-unit",
            format!("systemctl is not installed; cannot read whether {SERVICE} is enabled"),
        );
    }
    let output = timeout(
        Duration::from_secs(2),
        tokio::process::Command::new("systemctl")
            .args(["--user", "is-enabled", SERVICE])
            .kill_on_drop(true)
            .output(),
    )
    .await;
    match output {
        Ok(Ok(output)) => {
            let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if output.status.success() {
                CheckLine::pass("user-unit", format!("{SERVICE} is {state}"))
            } else {
                let mut reason = state;
                if reason.is_empty() {
                    reason = String::from_utf8_lossy(&output.stderr).trim().to_string();
                }
                if reason.is_empty() {
                    reason = format!("systemctl exited with {}", output.status);
                }
                CheckLine::warn(
                    "user-unit",
                    format!("{SERVICE} is not enabled ({reason}); run `seuil setup` in Desktop Mode"),
                )
            }
        }
        Ok(Err(error)) => CheckLine::warn(
            "user-unit",
            format!("could not run systemctl: {error}"),
        ),
        Err(_) => CheckLine::warn(
            "user-unit",
            "systemctl did not answer within 2 s; is the user manager running?".into(),
        ),
    }
}

/// Reports SteamOS/Steam Deck detection. Advisory only.
fn probe_steamos() -> CheckLine {
    let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let steamos = os_release.lines().any(|line| {
        let line = line.trim().to_ascii_lowercase();
        (line.starts_with("id=") || line.starts_with("id_like=")) && line.contains("steamos")
    });
    let deck = std::fs::read_to_string("/sys/devices/virtual/dmi/id/product_name")
        .map(|name| {
            let name = name.to_ascii_lowercase();
            name.contains("jupiter") || name.contains("galileo")
        })
        .unwrap_or(false);

    if steamos || deck {
        CheckLine::info(
            "steamos",
            "SteamOS/Steam Deck detected; install under $HOME and run setup in Desktop Mode".into(),
        )
    } else {
        CheckLine::info("steamos", "not detected; a generic Linux install applies".into())
    }
}

/// Resolves the phone address from the flag, config.toml, or the enrolled
/// account device list.
fn phone_address(cli: &Cli) -> Option<String> {
    if !cli.phone.is_empty() {
        return Some(cli.phone.clone());
    }
    let file = config::load();
    if let Some(phone) = file.phone_mac {
        return Some(phone);
    }
    let credentials = Credentials::load().ok().flatten();
    config::discover_phone(credentials.as_ref())
}

/// Reads the account fingerprint used to deobfuscate the advertisement.
fn fingerprint(cli: &Cli) -> Option<Vec<u8>> {
    if let Some(value) = cli.account_fingerprint.as_deref()
        && let Ok(bytes) = hex::decode(value)
        && !bytes.is_empty()
    {
        return Some(bytes);
    }
    let credentials = Credentials::load().ok().flatten()?;
    let bytes = hex::decode(credentials.user_fingerprint).ok()?;
    if bytes.is_empty() { None } else { Some(bytes) }
}

/// Reports whether `name` resolves to an executable on `PATH` without running
/// it, so a probe never hangs on a tool that is merely slow.
pub fn command_available(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join(name);
        std::fs::metadata(&candidate)
            .map(|metadata| metadata.is_file() && is_executable(&metadata))
            .unwrap_or(false)
    })
}

fn is_executable(metadata: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}
