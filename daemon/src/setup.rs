//! Interactive first-time setup.
//!
//! `seuil setup [--reauth]` enrolls the Samsung account when needed, lists the
//! BlueZ paired devices for the user to pick from, writes the config, and
//! installs and starts the systemd user unit.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

use crate::auth::Credentials;
use crate::{config, Cli};

/// Systemd unit name, also the service name.
const SERVICE: &str = "seuil.service";

/// Which role a paired device most likely plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Phone,
    Buds,
    Other,
}

impl Role {
    fn label(self) -> &'static str {
        match self {
            Role::Phone => "phone",
            Role::Buds => "buds",
            Role::Other => "device",
        }
    }
}

/// One paired BlueZ device shown in the picker.
#[derive(Debug, Clone)]
struct PairedDevice {
    address: String,
    name: String,
    role: Role,
}

/// Classifies a device by Bluetooth major device class and its name.
fn classify(class: Option<u32>, name: &str) -> Role {
    let major = class.map(|value| (value >> 8) & 0x1F).unwrap_or(0);
    let lower = name.to_ascii_lowercase();
    if lower.contains("buds") {
        return Role::Buds;
    }
    if major == 0x04 {
        return Role::Buds;
    }
    if major == 0x02 || lower.contains("galaxy") || lower.contains("samsung") {
        return Role::Phone;
    }
    Role::Other
}

/// Runs the setup wizard.
pub async fn run(cli: &Cli, reauth: bool) -> Result<()> {
    println!("Seuil setup");

    ensure_enrolled(cli, reauth).await?;

    let devices = paired_devices(&cli.adapter).await?;
    if devices.is_empty() {
        anyhow::bail!(
            "no paired Bluetooth devices found; pair the phone and the Buds in \
             bluetoothctl first, then re-run `seuil setup`"
        );
    }

    println!("\nPaired Bluetooth devices:");
    for (index, device) in devices.iter().enumerate() {
        println!(
            "{:>3}. {:<32} {}  [{}]",
            index + 1,
            device.name,
            device.address,
            device.role.label()
        );
    }

    let phone_default = devices.iter().position(|d| d.role == Role::Phone);
    let buds_default = devices.iter().position(|d| d.role == Role::Buds);
    let phone_index = prompt_index("Phone number", phone_default, devices.len())?;
    let buds_index = prompt_index("Buds number", buds_default, devices.len())?;
    if phone_index == buds_index {
        anyhow::bail!("the phone and the Buds must be different devices");
    }
    let phone = devices[phone_index].address.clone();
    let buds = devices[buds_index].address.clone();

    let dir = config::config_dir();
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create {}", dir.display()))?;
    let config_path = dir.join("config.toml");
    let text = format!(
        "# Seuil configuration\nphone_mac = \"{phone}\"\nbuds_mac = \"{buds}\"\n# adapter = \"{}\"\n# discover = true\n",
        cli.adapter
    );
    std::fs::write(&config_path, text)
        .with_context(|| format!("write {}", config_path.display()))?;
    println!("\nWrote {}", config_path.display());

    install_service()?;
    println!("Installed and started {SERVICE}");
    println!("Check the connection with: journalctl --user -u {SERVICE} -f");
    Ok(())
}

/// Enrolls the Samsung account when no credentials exist or `--reauth` is set.
async fn ensure_enrolled(cli: &Cli, reauth: bool) -> Result<()> {
    let credentials = Credentials::load()?;
    let enrolled = credentials
        .as_ref()
        .is_some_and(|stored| !stored.account_key.is_empty());
    if enrolled && !reauth {
        println!("Samsung account already enrolled");
        return Ok(());
    }

    println!("Samsung account enrollment (a browser window opens for sign-in)");
    let mut auth_args: Vec<String> = vec![
        "seuil".into(),
        "--auth-login".into(),
        "--auth-server".into(),
        cli.auth_server.clone(),
        "--adapter".into(),
        cli.adapter.clone(),
    ];
    if let Some(address) = &cli.bt_address {
        auth_args.push("--bt-address".into());
        auth_args.push(address.clone());
    }
    let auth_cli = Cli::parse_from(auth_args);
    crate::run_auth(&auth_cli).await?;
    info!("Samsung account enrollment complete");
    Ok(())
}

/// Lists paired BlueZ devices with a likely role.
async fn paired_devices(adapter_name: &str) -> Result<Vec<PairedDevice>> {
    let session = bluer::Session::new().await?;
    let adapter = session.adapter(adapter_name)?;
    adapter.set_powered(true).await?;

    let mut devices = Vec::new();
    for address in adapter.device_addresses().await? {
        let Ok(device) = adapter.device(address) else {
            continue;
        };
        if !device.is_paired().await.unwrap_or(false) {
            continue;
        }
        let alias = device.alias().await.unwrap_or_default();
        let name = device.name().await.ok().flatten().unwrap_or_default();
        let label = if !alias.is_empty() { alias } else { name };
        let class = device.class().await.unwrap_or(None);
        devices.push(PairedDevice {
            address: address.to_string(),
            role: classify(class, &label),
            name: label,
        });
    }
    devices.sort_by(|a, b| {
        let rank = |role: Role| match role {
            Role::Phone => 0,
            Role::Buds => 1,
            Role::Other => 2,
        };
        rank(a.role)
            .cmp(&rank(b.role))
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(devices)
}

/// Reads a 1-based list number, defaulting to `suggested` on an empty line.
fn prompt_index(label: &str, suggested: Option<usize>, len: usize) -> Result<usize> {
    loop {
        match suggested {
            Some(index) => print!("{label} [{}]: ", index + 1),
            None => print!("{label} (1-{len}): "),
        }
        io::stdout().flush()?;
        let mut line = String::new();
        if io::stdin().read_line(&mut line)? == 0 {
            anyhow::bail!("no input available; pass the MACs with flags or config.toml");
        }
        let line = line.trim();
        if line.is_empty() {
            if let Some(index) = suggested {
                return Ok(index);
            }
            continue;
        }
        match line.parse::<usize>() {
            Ok(value) if (1..=len).contains(&value) => return Ok(value - 1),
            _ => println!("Enter a number between 1 and {len}."),
        }
    }
}

/// Writes the systemd user unit and enables it.
fn install_service() -> Result<()> {
    let unit_path = unit_path()?;
    if let Some(parent) = unit_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&unit_path, unit_text())
        .with_context(|| format!("write {}", unit_path.display()))?;

    let bin = home_dir()?.join(".local/bin/seuil");
    if !bin.exists() {
        println!(
            "warning: {} is missing; run ./install.sh first",
            bin.display()
        );
    }

    run_systemctl(&["--user", "daemon-reload"])?;
    run_systemctl(&["--user", "enable", "--now", SERVICE])?;
    Ok(())
}

/// Path of the user unit.
pub fn unit_path() -> Result<PathBuf> {
    Ok(config::config_dir()
        .parent()
        .map(|base| base.join("systemd/user").join(SERVICE))
        .unwrap_or_else(|| PathBuf::from(SERVICE)))
}

/// Contents of the user unit.
pub fn unit_text() -> String {
    "[Unit]\n\
         Description=Seuil Samsung Continuity daemon (Galaxy Buds Auto Switch)\n\
         After=pipewire.service bluetooth.target\n\
         Wants=pipewire.service\n\
         PartOf=graphical-session.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart=%h/.local/bin/seuil\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         Environment=RUST_LOG=info\n\
         ExecStartPre=-/usr/bin/bluetoothctl show\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n".to_string()
}

fn run_systemctl(args: &[&str]) -> Result<()> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .context("run systemctl")?;
    if !status.success() {
        anyhow::bail!("systemctl {} exited with {status}", args.join(" "));
    }
    Ok(())
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_buds_by_name() {
        assert_eq!(classify(None, "Buds Core"), Role::Buds);
        assert_eq!(classify(Some(0x240404), "Headset"), Role::Buds);
    }

    #[test]
    fn classifies_phones_by_major_class() {
        assert_eq!(classify(Some(0x005A020C), "Galaxy A57"), Role::Phone);
        assert_eq!(classify(None, "Galaxy S24"), Role::Phone);
    }

    #[test]
    fn classifies_unknown_devices_as_other() {
        assert_eq!(classify(Some(0x001F0100), "Keyboard"), Role::Other);
    }

    #[test]
    fn unit_starts_the_rebranded_binary() {
        let unit = unit_text();
        assert!(unit.contains("ExecStart=%h/.local/bin/seuil"));
        assert!(unit.contains("After=pipewire.service bluetooth.target"));
    }
}
