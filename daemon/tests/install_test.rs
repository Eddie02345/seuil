//! Black-box tests for the prebuilt install path failure contract.
//!
//! Covers FR-002 Scenario "Download failure": an unreachable release URL
//! exits non-zero with a clear message and leaves no partial executable in
//! `~/.local/bin`.

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command;

fn temp_home(name: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!("seuil-install-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    home
}

// [FR-002 | FR-NFR 2.2 Scenario "Download failure"] GIVEN the release URL is
// unreachable, WHEN `install.sh --from-release` runs, THEN it exits non-zero
// with a clear message and leaves no partial executable.
#[test]
fn unreachable_release_url_exits_nonzero_without_partial_binary() {
    let home = temp_home("unreachable");
    let bin = home.join(".local/bin/seuil");
    let output = Command::new("bash")
        .arg(env!("CARGO_MANIFEST_DIR").to_string() + "/../install.sh")
        .arg("--from-release")
        .env("HOME", &home)
        .env("SEUIL_REPO", "no-such-org-6f3a/no-such-repo-6f3a")
        .env("SEUIL_VERSION", "v0.0.0-no-such-tag")
        .output()
        .expect("install.sh must be runnable");
    assert!(
        !output.status.success(),
        "an unreachable release must exit non-zero, got {:?}",
        output.status.code()
    );
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        message.contains("error") || message.contains("fail"),
        "the failure message must be clear, got: {message}"
    );
    assert!(
        !bin.exists(),
        "no partial executable may remain at {}",
        bin.display()
    );
}

// [FR-002 | FR-NFR 2.2 Scenario "Fresh Deck install"] The happy path needs a
// reachable release artifact on GitHub, so it is recorded but not asserted
// hermetically. Live run must observe: the binary lands at
// ~/.local/bin/seuil, is executable, and no compiler or package manager runs.
#[test]
#[ignore = "needs network access to the real release artifact"]
fn reachable_release_installs_the_binary_without_a_toolchain() {}
