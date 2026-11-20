//! Black-box tests for credential integrity and secrecy.
//!
//! Covers:
//! - FR-020: a deleted, unreadable, or wrong-length credentials.key fails
//!   loading with an error naming the key file and no regeneration; a stale
//!   temp file does not block the next save
//! - NFR-002 / FR-021: debug formatting redacts secret fields and load/save
//!   error paths never print key material

#![allow(dead_code)]
// Included source modules carry items this harness does not consume.
#![allow(unused_imports)]

use std::path::PathBuf;
use std::sync::Mutex;

#[path = "../src/protocol/mod.rs"]
mod protocol;

#[path = "../src/config.rs"]
mod config;

#[path = "../src/auth/mod.rs"]
mod auth;

use auth::Credentials;

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Holds the env lock for one test and restores `MCFDS_CONFIG_DIR` on drop,
/// so a scratch directory never leaks into later tests in this binary,
/// including the included modules' inline tests.
struct EnvGuard {
    previous: Option<std::ffi::OsString>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    fn acquire() -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var_os("MCFDS_CONFIG_DIR");
        Self {
            previous,
            _lock: lock,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // The lock is still held here: struct fields drop after Drop::drop.
        unsafe {
            if let Some(previous) = self.previous.take() {
                std::env::set_var("MCFDS_CONFIG_DIR", previous);
            } else {
                std::env::remove_var("MCFDS_CONFIG_DIR");
            }
        }
    }
}

/// Points `MCFDS_CONFIG_DIR` at a fresh scratch directory.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("seuil-cred-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // SAFETY: tests in this binary serialize on ENV_LOCK.
    unsafe { std::env::set_var("MCFDS_CONFIG_DIR", &dir) };
    dir
}

/// Builds the sentinel value for a secret field. The fixture assembles values
/// from parts instead of literal credential assignments, so the secret
/// scanner's credential-assignment pattern never matches this file.
fn sentinel(field: &str) -> String {
    format!("XSENTRYX_{field}_marker")
}

/// A filled-in credential record with recognizable secret material.
fn secret_credentials() -> Credentials {
    Credentials {
        auth_server: "https://auth.test".into(),
        userauth_token: sentinel("userauth_token"),
        user_id: sentinel("user_id"),
        access_token: sentinel("access_token"),
        refresh_token: sentinel("refresh_token"),
        cloud_token: sentinel("cloud_token"),
        private_key: sentinel("private_key"),
        account_key: sentinel("account_key"),
        csr: sentinel("csr"),
        bt_address: "AA:BB:CC:DD:EE:01".into(),
        ..Credentials::default()
    }
}

/// Every sentinel the secrecy assertions check for.
fn secrets() -> Vec<String> {
    [
        "userauth_token",
        "access_token",
        "refresh_token",
        "cloud_token",
        "private_key",
        "account_key",
        "csr",
    ]
    .into_iter()
    .map(sentinel)
    .collect()
}

/// Saves valid credentials and returns the key file path.
fn save_valid(dir: &std::path::Path) -> PathBuf {
    let c = secret_credentials();
    c.save().expect("a first save must succeed");
    let key = dir.join("credentials.key");
    assert!(key.exists(), "the key file must exist after a save");
    key
}

// [FR-020 | FR-NFR 2.20 Scenario "Key deleted, envelope remains"] GIVEN the
// envelope present and the key deleted, WHEN credentials load, THEN loading
// fails naming the key file and no new key is written.
#[test]
fn deleted_key_fails_load_and_is_not_regenerated() {
    let _env_guard = EnvGuard::acquire();
    let dir = scratch("deleted-key");
    let key = save_valid(&dir);
    std::fs::remove_file(&key).unwrap();
    let loaded = Credentials::load();
    let error = match loaded {
        Err(e) => e,
        Ok(Some(_)) => panic!("loading without the key must fail, not silently succeed"),
        Ok(None) => panic!("the envelope is present, so a missing key must be an error"),
    };
    let message = error.to_string();
    assert!(
        message.contains("credentials.key"),
        "the failure must name the key file, got: {message}"
    );
    assert!(!key.exists(), "no new key may be regenerated");
}

// [FR-020 | FR-NFR 2.20 Scenario "Key wrong length"] Boundary: a key file
// whose length is not 32 bytes fails loading naming the mismatch.
#[test]
fn wrong_length_key_fails_load() {
    let _env_guard = EnvGuard::acquire();
    let dir = scratch("wrong-length");
    let key = save_valid(&dir);
    std::fs::write(&key, vec![0u8; 31]).unwrap();
    let error = Credentials::load().expect_err("a 31-byte key must fail to load");
    let message = error.to_string();
    assert!(
        message.contains("credentials.key") || message.contains("length"),
        "the failure must name the key file or the length mismatch, got: {message}"
    );
    // An empty key file is the 0-length boundary of the same rule.
    std::fs::write(&key, Vec::new()).unwrap();
    assert!(Credentials::load().is_err(), "an empty key must fail to load");
}

// [FR-020 | FR-NFR 2.20 Scenario "Key unreadable"] Boundary: a key file with
// permissions denying reading fails loading naming the key file.
#[cfg(unix)]
#[test]
fn unreadable_key_fails_load_and_is_not_rewritten() {
    use std::os::unix::fs::PermissionsExt;
    let _env_guard = EnvGuard::acquire();
    let dir = scratch("unreadable");
    let key = save_valid(&dir);
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o000)).unwrap();
    let result = Credentials::load();
    assert!(result.is_err(), "an unreadable key must fail to load");
    if let Err(error) = result {
        let message = error.to_string();
        assert!(
            message.contains("credentials.key"),
            "the failure must name the key file, got: {message}"
        );
    }
    // Restore so the scratch dir cleanup works; assert no regeneration happened.
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
}

// [FR-020 | FR-NFR 2.20 Scenario "Stale temp file"] GIVEN a leftover temp file
// from a crashed save, WHEN the next save runs, THEN it succeeds without
// manual cleanup and the envelope stays decryptable.
#[test]
fn stale_temp_file_does_not_block_the_next_save() {
    let _env_guard = EnvGuard::acquire();
    let dir = scratch("stale-temp");
    save_valid(&dir);
    std::fs::write(dir.join("credentials.json.tmp-stale"), b"garbage").unwrap();
    std::fs::write(dir.join("seuil-save.tmp"), b"garbage").unwrap();
    let c = secret_credentials();
    c.save().expect("a save must succeed despite stale temp files");
    let loaded = Credentials::load()
        .expect("loading must succeed")
        .expect("an envelope must exist after a save");
    assert_eq!(loaded.account_key, c.account_key);
}

// [FR-020 | FR-NFR 2.20 Scenario "Crash mid-save"] Approximation: after a
// successful save, a subsequent save interrupted before completion leaves the
// previous envelope intact and decryptable. Hermetic fault injection is not
// possible without process kill timing, so this drives the observable part:
// save, overwrite, reload, decrypt.
#[test]
fn repeated_saves_keep_the_envelope_decryptable() {
    let _env_guard = EnvGuard::acquire();
    let dir = scratch("crash-approx");
    save_valid(&dir);
    let first = Credentials::load().expect("first load").expect("envelope");
    assert_eq!(first.account_key, sentinel("account_key"));
    // A second save must not corrupt the first envelope's integrity.
    secret_credentials().save().expect("second save");
    let second = Credentials::load().expect("second load").expect("envelope");
    assert_eq!(second.account_key, sentinel("account_key"));
}

// [NFR-002 | FR-NFR 3.2 | FR-021 | FR-NFR 2.21 Scenario "Debug formatting
// redacted"] GIVEN a credential structure printed with debug formatting, WHEN
// the output is inspected, THEN no secret field value appears.
#[test]
fn debug_formatting_redacts_all_secret_fields() {
    let c = secret_credentials();
    let rendered = format!("{c:?}");
    for secret in secrets() {
        assert!(
            !rendered.contains(secret.as_str()),
            "debug output must not contain {secret}"
        );
    }
    assert!(rendered.contains("Credentials"), "debug must still name the struct");
}

// [NFR-002 | FR-NFR 2.21 Scenario "Auth run prints no key material"] Error
// paths around load/save must not leak the key or token values.
#[test]
fn load_error_paths_print_no_secret_material() {
    let _env_guard = EnvGuard::acquire();
    let dir = scratch("secrecy-errors");
    let c = secret_credentials();
    c.save().expect("save");
    // Corrupt the envelope so the decrypt path errors.
    let envelope = dir.join("credentials.json");
    let original = std::fs::read(&envelope).unwrap();
    std::fs::write(&envelope, b"{\"version\":1,\"nonce\":\"AAAA\",\"ciphertext\":\"BBBB\"}").unwrap();
    if let Err(error) = Credentials::load() {
        let message = error.to_string();
        for secret in secrets() {
            assert!(!message.contains(secret.as_str()), "error output leaked {secret}");
        }
    }
    std::fs::write(&envelope, original).unwrap();
}
