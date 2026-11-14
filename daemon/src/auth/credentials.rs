//! Encrypted credential storage for the Samsung account session.
//!
//! The daemon stores tokens, the enrollment CSR, and the account key bundle in
//! `$XDG_CONFIG_HOME/seuil/credentials.json`, encrypted with AES-256-GCM
//! under a random local key in `credentials.key`. Both files are created with
//! owner-only permissions.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::crypto::{base64_standard, random_bytes};
use super::{AuthError, DeviceInfo, Result};

const DATA_FILE: &str = "credentials.json";
const KEY_FILE: &str = "credentials.key";
const ENVELOPE_VERSION: u8 = 1;
// Stable across the linux-mcfds -> seuil rename so existing credential
// stores stay decryptable after migration.
const AAD: &[u8] = b"linux-mcfds-credentials-v1";

/// Persisted Samsung account session. Never log this value.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Credentials {
    pub auth_server: String,
    pub userauth_token: String,
    pub user_id: String,
    pub login_id: String,
    pub device_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires: i64,
    pub registration_id: String,
    pub cloud_token: String,
    pub cloud_expires: i64,
    pub csr: String,
    pub private_key: String,
    pub bt_address: String,
    pub account_key: String,
    pub user_fingerprint: String,
    pub revision: u32,
    pub devices: Vec<DeviceInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    version: u8,
    nonce: String,
    ciphertext: String,
}

impl Credentials {
    pub fn load() -> Result<Option<Self>> {
        Self::load_from(&config_dir())
    }

    fn load_from(dir: &Path) -> Result<Option<Self>> {
        let path = dir.join(DATA_FILE);
        reject_symlink(&path)?;
        match fs::read(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
            Ok(_) => {}
        }

        let key = read_key(dir)?;
        let raw = fs::read(&path)?;
        let envelope: Envelope = serde_json::from_slice(&raw)?;
        if envelope.version != ENVELOPE_VERSION {
            return Err(AuthError::Protocol(format!(
                "credentials file version {} is not supported",
                envelope.version
            )));
        }
        let nonce = STANDARD
            .decode(&envelope.nonce)
            .map_err(|e| AuthError::Crypto(format!("invalid credentials nonce: {e}")))?;
        let ciphertext = STANDARD
            .decode(&envelope.ciphertext)
            .map_err(|e| AuthError::Crypto(format!("invalid credentials payload: {e}")))?;
        if nonce.len() != 12 {
            return Err(AuthError::Crypto(
                "stored credentials nonce has an invalid length".into(),
            ));
        }
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| AuthError::Crypto(format!("invalid credentials key: {e}")))?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: AAD,
                },
            )
            .map_err(|_| AuthError::Crypto("stored credentials could not be decrypted".into()))?;
        debug!(path = %path.display(), "Loaded Samsung credentials");
        Ok(Some(serde_json::from_slice(&plaintext)?))
    }

    pub fn save(&self) -> Result<()> {
        self.save_to(&config_dir())
    }

    fn save_to(&self, dir: &Path) -> Result<()> {
        create_private_dir(dir)?;
        let key = read_key(dir)?;
        let plaintext = serde_json::to_vec(self)?;
        let nonce = random_bytes(12);
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| AuthError::Crypto(format!("invalid credentials key: {e}")))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: AAD,
                },
            )
            .map_err(|_| AuthError::Crypto("credentials could not be encrypted".into()))?;
        let envelope = Envelope {
            version: ENVELOPE_VERSION,
            nonce: base64_standard(&nonce),
            ciphertext: base64_standard(&ciphertext),
        };
        let path = dir.join(DATA_FILE);
        write_private(&path, &serde_json::to_vec(&envelope)?)?;
        debug!(path = %path.display(), "Saved Samsung credentials");
        Ok(())
    }

    /// Decodes the stored 32-byte AES-GCM account key used for the LAN handshake.
    ///
    /// Returns `None` when no key is stored or it is not 32 bytes of hex.
    pub fn account_key(&self) -> Option<[u8; 32]> {
        hex::decode(&self.account_key).ok()?.try_into().ok()
    }

    /// Decodes the stored Bluetooth address into its six raw bytes.
    pub fn bt_address_bytes(&self) -> Result<[u8; 6]> {
        let normalized = super::normalize_bt_address(&self.bt_address)?;
        let digits: String = normalized
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();
        let bytes = hex::decode(digits).map_err(|e| {
            AuthError::Protocol(format!("stored Bluetooth address is not valid hex: {e}"))
        })?;
        bytes.try_into().map_err(|_| {
            AuthError::Protocol("stored Bluetooth address must contain six bytes".into())
        })
    }
}

pub fn data_path() -> PathBuf {
    config_dir().join(DATA_FILE)
}

fn config_dir() -> PathBuf {
    crate::config::config_dir()
}

fn read_key(dir: &Path) -> Result<[u8; 32]> {
    let path = dir.join(KEY_FILE);
    reject_symlink(&path)?;
    match fs::read(&path) {
        Ok(bytes) if bytes.len() == 32 => Ok(bytes.try_into().expect("length checked")),
        Ok(_) => Err(AuthError::Crypto(
            "local credentials key has an invalid length".into(),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            create_private_dir(dir)?;
            let key = random_bytes(32);
            write_private(&path, &key)?;
            Ok(key.try_into().expect("length is 32"))
        }
        Err(e) => Err(e.into()),
    }
}

fn reject_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(AuthError::Protocol(format!(
            "refusing to use symlinked credentials path {}",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn create_private_dir(dir: &Path) -> Result<()> {
    reject_symlink(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(dir)?;
    Ok(())
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    reject_symlink(path)?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    create_private_dir(dir)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("credentials");
    let temp = dir.join(format!(".{file_name}.{}.tmp", std::process::id()));

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    if let Err(e) = file.write_all(data).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(e.into());
    }
    drop(file);
    fs::rename(&temp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "linux-mcfds-credentials-{}-{unique}",
            std::process::id()
        ))
    }

    #[test]
    fn credentials_round_trip_through_encrypted_file() {
        let dir = temp_dir();
        let credentials = Credentials {
            device_id: "device-123".into(),
            user_fingerprint: "ab".repeat(32),
            ..Credentials::default()
        };
        credentials.save_to(&dir).expect("save");
        let loaded = Credentials::load_from(&dir)
            .expect("load")
            .expect("credentials present");
        assert_eq!(loaded.device_id, "device-123");
        assert_eq!(loaded.user_fingerprint, "ab".repeat(32));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join(DATA_FILE))
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn missing_credentials_returns_none() {
        let dir = temp_dir();
        assert!(Credentials::load_from(&dir).expect("load").is_none());
        assert!(!dir.exists());
    }

    #[test]
    fn interrupted_save_leaves_previous_envelope_loadable() {
        let dir = temp_dir();
        let first = Credentials {
            device_id: "device-old".into(),
            ..Credentials::default()
        };
        first.save_to(&dir).expect("first save");

        // Simulate an interrupted save: a stale temp file with partial data
        // exists, but the rename never happened. Use a pid that cannot collide
        // with this process so the later save still creates its own temp file.
        let stale = dir.join(format!(".{DATA_FILE}.999999.tmp"));
        fs::write(&stale, b"{\"partial\"").expect("stale temp file");
        assert_eq!(
            Credentials::load_from(&dir)
                .expect("load after interrupted save")
                .expect("previous credentials present")
                .device_id,
            "device-old"
        );

        // A completed save replaces the envelope and the next load picks it up.
        let second = Credentials {
            device_id: "device-new".into(),
            ..Credentials::default()
        };
        second.save_to(&dir).expect("second save");
        assert_eq!(
            Credentials::load_from(&dir)
                .expect("load after completed save")
                .expect("credentials present")
                .device_id,
            "device-new"
        );

        fs::remove_dir_all(&dir).expect("cleanup");
    }
}
