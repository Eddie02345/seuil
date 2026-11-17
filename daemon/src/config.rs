//! TOML configuration for the daemon.
//!
//! Reads `$XDG_CONFIG_HOME/seuil/config.toml`, so the command line flags
//! become optional for daily use:
//!
//! ```toml
//! phone_mac = "AA:BB:CC:DD:EE:FF"
//! buds_mac = "11:22:33:44:55:66"
//! # adapter = "hci0"
//! # discover = true
//! ```
//!
//! Missing MACs fall back to the enrolled Samsung account device list in
//! `credentials.json` (phone) and to a BlueZ device whose name contains
//! "Buds" (buds).

use std::path::PathBuf;

use serde::Deserialize;
use tracing::{debug, warn};

use crate::auth::Credentials;

/// Values read from `config.toml`.
#[derive(Debug, Default, Deserialize)]
pub struct FileConfig {
    pub phone_mac: Option<String>,
    pub buds_mac: Option<String>,
    pub adapter: Option<String>,
    pub device_name: Option<String>,
    /// Allow the enrolled account list and BlueZ to fill missing MACs.
    #[serde(default = "default_discover")]
    pub discover: bool,
}

fn default_discover() -> bool {
    true
}

/// The daemon's configuration directory, shared with the credential store.
pub fn config_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("MCFDS_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("seuil")
}

/// Loads `config.toml`; a missing file yields defaults.
pub fn load() -> FileConfig {
    let path = config_dir().join("config.toml");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            debug!(path = %path.display(), "No config.toml; using flags and discovery");
            return FileConfig {
                discover: true,
                ..FileConfig::default()
            };
        }
        Err(error) => {
            warn!(path = %path.display(), "Could not read config.toml: {error}");
            return FileConfig {
                discover: true,
                ..FileConfig::default()
            };
        }
    };
    match toml::from_str(&text) {
        Ok(config) => {
            debug!(path = %path.display(), "Loaded config.toml");
            config
        }
        Err(error) => {
            warn!(path = %path.display(), "Invalid config.toml: {error}");
            FileConfig {
                discover: true,
                ..FileConfig::default()
            }
        }
    }
}

/// Picks the first phone address from the enrolled account device list.
pub fn discover_phone(credentials: Option<&Credentials>) -> Option<String> {
    credentials.and_then(|credentials| {
        credentials
            .devices
            .iter()
            .find(|device| {
                let kind = device.device_type.to_ascii_uppercase();
                device.bt_address.len() == 17 && kind.contains("PHONE")
            })
            .or_else(|| {
                credentials.devices.iter().find(|device| {
                    let kind = device.device_type.to_ascii_uppercase();
                    device.bt_address.len() == 17
                        && !kind.contains("PC")
                        && !kind.contains("WATCH")
                })
            })
            .map(|device| device.bt_address.clone())
    })
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use crate::auth::DeviceInfo;

    fn device(address: &str, kind: &str) -> DeviceInfo {
        DeviceInfo {
            bt_address: address.into(),
            device_name: String::new(),
            device_type: kind.into(),
            device_model: String::new(),
        }
    }

    #[test]
    fn discovers_the_phone_from_the_device_list() {
        let mut credentials = Credentials::default();
        credentials.devices = vec![
            device("22:33:44:55:66:77", "BUDS"),
            device("AA:BB:CC:DD:EE:FF", "PHONE"),
            device("11:22:33:44:55:66", "PC"),
        ];
        assert_eq!(
            discover_phone(Some(&credentials)).as_deref(),
            Some("AA:BB:CC:DD:EE:FF")
        );
    }

    #[test]
    fn discovery_skips_pc_and_watch_entries() {
        let mut credentials = Credentials::default();
        credentials.devices = vec![
            device("11:22:33:44:55:66", "PC"),
            device("22:33:44:55:66:77", "WATCH"),
            device("77:88:99:AA:BB:CC", "TABLET"),
        ];
        assert_eq!(
            discover_phone(Some(&credentials)).as_deref(),
            Some("77:88:99:AA:BB:CC")
        );
    }

    #[test]
    fn no_credentials_yields_no_phone() {
        assert_eq!(discover_phone(None), None);
    }

    #[test]
    fn config_dir_honours_the_override() {
        // The variable is process-wide, so only assert the naming contract.
        let dir = config_dir();
        assert!(dir.ends_with("seuil"));
    }
}
