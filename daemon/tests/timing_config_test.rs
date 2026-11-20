//! Black-box boundary tests for the configured timing values.
//!
//! Covers the settled defaults and the custom-override contract:
//! - FR-010: dwell 10 s default, backoff start 1 s, backoff cap 60 s, all configurable
//! - FR-012: keepalive and frame read timeouts default 10 s each, peer map cap 256
//! - FR-016: media threshold -60 dBFS and 200 ms window defaults, configurable
//! - FR-022: an invalid config.toml aborts with an error naming the file
//!
//! Reached through the crate-include mechanism sanctioned by the task plan:
//! `#[path = "../src/..."] mod ...;` on a binary-only crate.

#![allow(dead_code)]
// Included source modules carry items this harness does not consume.
#![allow(unused_imports)]

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

#[path = "../src/protocol/mod.rs"]
mod protocol;

#[path = "../src/auth/mod.rs"]
mod auth;

#[path = "../src/config.rs"]
mod config;

/// Serializes env-var mutation across tests in this binary.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Point `MCFDS_CONFIG_DIR` at a scratch directory and drop a config.toml in it.
fn with_config(toml: Option<&str>) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("seuil-timing-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    if let Some(text) = toml {
        std::fs::write(dir.join("config.toml"), text).unwrap();
    } else {
        let _ = std::fs::remove_file(dir.join("config.toml"));
    }
    // SAFETY: tests in this binary serialize on ENV_LOCK.
    unsafe { std::env::set_var("MCFDS_CONFIG_DIR", &dir) };
    dir
}

// [FR-010 | FR-NFR 2.10 | spec-hardening-test-suite] Default boundary values.
// Boundary: the settled defaults (10 s dwell, 1 s backoff start, 60 s cap).
#[test]
fn default_config_carries_the_settled_dwell_and_backoff_values() {
    let _env_guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _dir = with_config(None);
    let cfg = config::load_strict().expect("an absent config.toml must load defaults");
    assert_eq!(cfg.handoff_dwell(), Duration::from_secs(10));
    assert_eq!(cfg.backoff_start(), Duration::from_secs(1));
    assert_eq!(cfg.backoff_cap(), Duration::from_secs(60));
}

// [FR-012 | FR-NFR 2.12] Default timeout boundaries: keepalive and frame reads
// are bounded at 10 s each and the per-peer bookkeeping cap is 256 entries.
#[test]
fn default_config_carries_the_settled_timeout_and_map_cap_values() {
    let _env_guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _dir = with_config(None);
    let cfg = config::load_strict().expect("an absent config.toml must load defaults");
    assert_eq!(cfg.keepalive_timeout(), Duration::from_secs(10));
    assert_eq!(cfg.frame_timeout(), Duration::from_secs(10));
    assert_eq!(cfg.peer_limit(), 256);
}

// [FR-016 | FR-NFR 2.16] Default audio-rule boundaries: -60 dBFS threshold and
// a 200 ms window.
#[test]
fn default_config_carries_the_settled_media_threshold_and_window() {
    let _env_guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _dir = with_config(None);
    let cfg = config::load_strict().expect("an absent config.toml must load defaults");
    assert_eq!(cfg.media_threshold_dbfs(), -60.0_f32);
    assert_eq!(cfg.media_window(), Duration::from_millis(200));
}

// [FR-010 | FR-NFR 2.10 Scenario "Custom configuration honored"] A custom
// dwell and backoff override the defaults.
#[test]
fn custom_dwell_and_backoff_values_override_the_defaults() {
    let _env_guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _dir = with_config(Some(
        "handoff_dwell_secs = 3\ncoc_backoff_start_secs = 2\ncoc_backoff_cap_secs = 45\n",
    ));
    let cfg = config::load_strict().expect("a valid config.toml must load");
    assert_eq!(cfg.handoff_dwell(), Duration::from_secs(3));
    assert_eq!(cfg.backoff_start(), Duration::from_secs(2));
    assert_eq!(cfg.backoff_cap(), Duration::from_secs(45));
}

// [FR-012 | FR-NFR 2.12] Custom keepalive, frame timeout, and peer map cap
// override the defaults.
#[test]
fn custom_timeout_and_peer_cap_values_override_the_defaults() {
    let _env_guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _dir = with_config(Some(
        "coc_keepalive_timeout_secs = 5\ncoc_frame_timeout_secs = 7\npeer_map_limit = 16\n",
    ));
    let cfg = config::load_strict().expect("a valid config.toml must load");
    assert_eq!(cfg.keepalive_timeout(), Duration::from_secs(5));
    assert_eq!(cfg.frame_timeout(), Duration::from_secs(7));
    assert_eq!(cfg.peer_limit(), 16);
}

// [FR-016 | spec-media-activity-filtering Requirement 1 Scenario "Custom thresholds"]
// A custom media threshold and window override the defaults.
#[test]
fn custom_media_threshold_and_window_override_the_defaults() {
    let _env_guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _dir = with_config(Some("media_threshold_dbfs = -40\nmedia_window_ms = 350\n"));
    let cfg = config::load_strict().expect("a valid config.toml must load");
    assert_eq!(cfg.media_threshold_dbfs(), -40.0_f32);
    assert_eq!(cfg.media_window(), Duration::from_millis(350));
}

// [FR-022 | FR-NFR 2.22 Scenario "TOML typo aborts"] A config.toml with a
// syntax error aborts loading with an error naming the file.
#[test]
fn invalid_config_aborts_with_an_error_naming_the_file() {
    let _env_guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _dir = with_config(Some("handoff_dwell_secs = = = broken\n"));
    let error = config::load_strict().expect_err("a syntax error must abort config loading");
    let message = error.to_string();
    assert!(
        message.contains("config.toml"),
        "the parse failure must name the config file, got: {message}"
    );
}

// [FR-010 | FR-NFR 2.10] Boundary: zero and negative configured timings clamp
// to at least one unit rather than producing zero-length waits.
#[test]
fn zero_configured_timings_clamp_to_one() {
    let _env_guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let _dir = with_config(Some(
        "handoff_dwell_secs = 0\ncoc_backoff_start_secs = 0\ncoc_backoff_cap_secs = 0\n",
    ));
    let cfg = config::load_strict().expect("a valid config.toml must load");
    assert_eq!(cfg.handoff_dwell(), Duration::from_secs(1));
    assert_eq!(cfg.backoff_start(), Duration::from_secs(1));
    assert_eq!(cfg.backoff_cap(), Duration::from_secs(1));
}
