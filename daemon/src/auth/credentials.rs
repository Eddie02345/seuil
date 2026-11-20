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

/// Placeholder shown for secret fields in `Debug` output.
const REDACTED: &str = "<redacted>";

/// Persisted Samsung account session. Never log this value.
#[derive(Clone, Default, Serialize, Deserialize)]
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
    #[serde(default)]
    pub device_name: String,
    pub devices: Vec<DeviceInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    version: u8,
    nonce: String,
    ciphertext: String,
}

/// [FR-021] Debug output names the fields but never prints key material,
/// tokens, the CSR, or the private key.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("auth_server", &self.auth_server)
            .field("userauth_token", &REDACTED)
            .field("user_id", &REDACTED)
            .field("login_id", &REDACTED)
            .field("device_id", &REDACTED)
            .field("access_token", &REDACTED)
            .field("refresh_token", &REDACTED)
            .field("access_expires", &self.access_expires)
            .field("registration_id", &REDACTED)
            .field("cloud_token", &REDACTED)
            .field("cloud_expires", &self.cloud_expires)
            .field("csr", &REDACTED)
            .field("private_key", &REDACTED)
            .field("bt_address", &REDACTED)
            .field("account_key", &REDACTED)
            .field("user_fingerprint", &REDACTED)
            .field("revision", &self.revision)
            .field("device_name", &self.device_name)
            .field("devices", &self.devices.len())
            .finish()
    }
}

impl Credentials {
    pub fn load() -> Result<Option<Self>> {
        Self::load_from(&config_dir()?)
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
        self.save_to(&config_dir()?)
    }

    fn save_to(&self, dir: &Path) -> Result<()> {
        create_private_dir(dir)?;
        let key = read_key_for_save(dir)?;
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
    crate::config::config_dir().join(DATA_FILE)
}

fn config_dir() -> Result<PathBuf> {
    crate::config::try_config_dir().map_err(|error| AuthError::Protocol(error.to_string()))
}

/// Reads the 32-byte AES key, failing rather than regenerating when it is
/// missing, unreadable, or the wrong length.
///
/// [FR-020] A regenerated key would orphan the encrypted envelope, so a missing
/// key is a load failure that names the key file.
fn read_key(dir: &Path) -> Result<[u8; 32]> {
    let path = dir.join(KEY_FILE);
    reject_symlink(&path)?;
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(AuthError::Protocol(format!(
                "credentials key {} is missing; restore it or rerun setup --reauth",
                path.display()
            )));
        }
        Err(error) => {
            return Err(AuthError::Protocol(format!(
                "credentials key {} could not be read: {error}",
                path.display()
            )));
        }
    };
    <[u8; 32]>::try_from(bytes).map_err(|bytes| {
        AuthError::Protocol(format!(
            "credentials key {} has length {}; expected 32 bytes",
            path.display(),
            bytes.len()
        ))
    })
}

/// Returns the AES key for a save, creating one when the key file is missing.
///
/// [FR-020] `save` rewrites the entire envelope, so a keyless store cannot be
/// read back anyway: creating a fresh key lets the doctor's `setup --reauth`
/// remedy complete. Load time stays strict: [`read_key`] still fails on a
/// missing key rather than orphaning an envelope it cannot decrypt.
fn read_key_for_save(dir: &Path) -> Result<[u8; 32]> {
    let key_path = dir.join(KEY_FILE);
    reject_symlink(&key_path)?;
    if key_path.exists() {
        return read_key(dir);
    }
    create_private_dir(dir)?;
    let key = random_bytes(32);
    write_private(&key_path, &key)?;
    <[u8; 32]>::try_from(key).map_err(|key| {
        AuthError::Crypto(format!(
            "generated credentials key has length {}; expected 32 bytes",
            key.len()
        ))
    })
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

    // [FR-020] A unique temp name means a leftover temp file from a crashed
    // save never blocks a later one, and concurrent writers cannot collide.
    let unique = hex::encode(random_bytes(8));
    let temp = dir.join(format!(
        ".{file_name}.{}.{unique}.tmp",
        std::process::id()
    ));

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let write_result = (|| -> std::io::Result<()> {
        let mut file = options.open(&temp)?;
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temp);
        return Err(error.into());
    }

    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error.into());
    }

    // [FR-020] Persist the rename itself so a crash cannot lose the new file.
    // A directory sync failure weakens durability only, so it does not fail the
    // save.
    #[cfg(unix)]
    if let Ok(dir_file) = fs::File::open(dir) {
        let _ = dir_file.sync_all();
    }
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

    #[test]
    fn save_creates_a_missing_key_over_an_existing_envelope() {
        let dir = temp_dir();
        Credentials {
            device_id: "device-old".into(),
            ..Credentials::default()
        }
        .save_to(&dir)
        .expect("first save");
        fs::remove_file(dir.join(KEY_FILE)).expect("remove key");

        // The strict load path still refuses the keyless store.
        assert!(Credentials::load_from(&dir).is_err());

        // A save rewrites the envelope, so it may mint a fresh key.
        Credentials {
            device_id: "device-new".into(),
            ..Credentials::default()
        }
        .save_to(&dir)
        .expect("save over a keyless store");
        assert_eq!(
            Credentials::load_from(&dir)
                .expect("load after key recovery")
                .expect("credentials present")
                .device_id,
            "device-new"
        );

        fs::remove_dir_all(&dir).expect("cleanup");
    }
}
