//! Interactive first-time setup.
//!
//! `seuil setup [--reauth]` enrolls the Samsung account when needed, lists the
//! BlueZ paired devices for the user to pick from, writes the config, and
//! installs and starts the systemd user unit.

use std::io::Write;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

use crate::auth::Credentials;
use crate::{Cli, config};

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
    println!("\nEnter a list number, or press Enter to accept the default.");
    let phone_index = prompt_index(
        "Select the phone by list number",
        phone_default,
        devices.len(),
    )
    .await?;
    let buds_index = prompt_index(
        "Select the Buds by list number",
        buds_default,
        devices.len(),
    )
    .await?;
    if phone_index == buds_index {
        anyhow::bail!("the phone and the Buds must be different devices");
    }
    let phone = devices[phone_index].address.clone();
    let buds = devices[buds_index].address.clone();

    let dir = config::config_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let config_path = dir.join("config.toml");
    let text = format!(
        "# Seuil configuration\nphone_mac = \"{phone}\"\nbuds_mac = \"{buds}\"\n# adapter = \"{}\"\n# discover = true\n",
        cli.adapter
    );
    std::fs::write(&config_path, text)
        .with_context(|| format!("write {}", config_path.display()))?;
    println!("\nWrote {}", config_path.display());

    println!("Setup completed!");
    println!("if you wish to, enable and start the systemd service with:");
    println!("systemctl --user enable --now seuil.service");
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
async fn prompt_index(label: &str, suggested: Option<usize>, len: usize) -> Result<usize> {
    loop {
        match suggested {
            Some(index) => print!("{label} (1-{len}) [default {}]: ", index + 1),
            None => print!("{label} (1-{len}): "),
        }
        std::io::stdout().flush()?;
        let Some(line) = crate::auth::read_stdin_line().await else {
            anyhow::bail!("no input available; pass the MACs with flags or config.toml");
        };
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
}
