//! Boundaries that need live hardware, root, or a running daemon session.
//!
//! Each test records the settled boundary it traces to and what a live run
//! must observe. They are compiled and reported, but marked `#[ignore]`
//! because they cannot be driven hermetically.

#![allow(dead_code)]

// [FR-009 | FR-NFR 2.9 Scenario "Suspend and wake"] Live run must observe:
// on logind PrepareForSleep(true) the CoC channel closes and scan and
// advertising stop; after wake exactly one advertisement, one discovery
// session, and one redial attempt exist, with no leaked tasks.
#[test]
#[ignore = "needs a real suspend/wake cycle on a live system"]
fn suspend_then_wake_converges_to_exactly_one_of_each() {}

// [FR-009 | FR-NFR 2.9 Scenario "Adapter power toggle"] Live run must
// observe: powering the adapter off and on reaches the same clean state as a
// wake without a service restart.
#[test]
#[ignore = "needs root to toggle adapter power"]
fn adapter_power_off_and_on_recovers_cleanly() {}

// [FR-023 | FR-NFR 2.23 Scenario "bluetoothd restart recovery"] and
// [NFR-004 | FR-NFR 3.3] Live run must observe: after bluetoothd restarts,
// the daemon re-acquires the adapter and session with backoff and resumes
// scanning and advertising within 60 s of bluetoothd becoming reachable.
#[test]
#[ignore = "needs root to restart bluetoothd on a live system"]
fn bluetoothd_restart_recovers_within_sixty_seconds() {}

// [FR-010 | FR-NFR 2.10 Scenario "Second request inside the dwell" /
// "Request after the dwell" / "Backoff sequence on repeated connect failures"]
// The dwell gate, the 1 s doubling backoff sequence, and the 60 s cap live in
// the daemon's dial path with no public seam; the configured default and
// custom values are covered hermetically in timing_config_test.rs and the
// sequence itself by the inline unit tests in the daemon crate. Live run must
// observe: a trigger inside 10 s of the previous handoff is suppressed and
// logged as dwell-blocked; one at or past 10 s proceeds; repeated connect
// failures delay 1, 2, 4, ... capped at 60 s; custom config.toml values are
// honored.
#[test]
#[ignore = "needs a live phone and the daemon dial path; the timing values are covered hermetically"]
fn dwell_and_backoff_boundaries_on_the_live_dial_path() {}

// [FR-012 | FR-NFR 2.12 Scenario "Stalled peer" / "Keepalive timeout tears
// down"] Live run must observe: a peer that stops responding mid-frame tears
// its channel down cleanly and removes the map entry when the configured
// frame timeout (default 10 s) expires; a peer that stops acknowledging
// keepalive writes is torn down at the keepalive timeout (default 10 s).
#[test]
#[ignore = "needs a live CoC peer that stalls mid-frame"]
fn stalled_peer_tears_down_at_the_configured_timeouts() {}

// [FR-012 | FR-NFR 2.12 Scenario "Rotating spoofed addresses"] Live run must
// observe: hours of rotating random advertisements keep every per-peer
// bookkeeping map within the configured cap (default 256 entries).
#[test]
#[ignore = "needs hours of live rotating-address traffic"]
fn rotating_addresses_respect_the_peer_map_cap() {}

// [FR-014 | FR-NFR 2.14] Live run must observe: a dial whose channel closes
// immediately leaves no entry blocking future dials to that peer; one peer's
// saturated channel does not stall another peer; a hung connect attempt does
// not accumulate duplicates.
#[test]
#[ignore = "needs live CoC peers to observe concurrency outcomes"]
fn concurrency_faults_have_their_settled_observable_outcomes() {}

// [FR-015 | FR-NFR 2.15] Live run must observe: a scan restart stops the
// previous discovery session before reapplying filters (exactly one session
// active afterward); a rejected filter logs a visible warning; an
// advertisement registration collision retries with backoff instead of
// exiting.
#[test]
#[ignore = "needs a live adapter to observe discovery and advertising sessions"]
fn scan_and_advertiser_supervision_boundaries() {}

// [FR-013 | FR-NFR 2.13 Scenario "Seamless handoff delivered"] Live run must
// observe: SET_SEAMLESS_CONNECTION reaches the Buds over SPP and the
// acknowledgement is processed after a yield to the phone completes.
#[test]
#[ignore = "needs live Buds SPP traffic"]
fn seamless_handoff_is_delivered_over_spp() {}

// [FR-019 | FR-NFR 2.19 Scenario "Teardown before reply" / "A2DP pull
// retries" / "Call-reason grant leaves media alone"] Live run must observe:
// the release reply follows verified pause and completed profile teardown;
// the A2DP connect retries within bounds before a warning; a call-reason
// grant initiates no A2DP pull.
#[test]
#[ignore = "needs a live phone and audio stack to observe release ordering"]
fn release_and_pull_ordering_on_live_profiles() {}

// [FR-023 | FR-NFR 2.23 Scenario "Token refresh at runtime" / "Certificate
// rotation escalates"] Live run must observe: a token inside the 120 s
// refresh margin refreshes and persists without user action while a token
// outside the margin does not trigger a refresh; rejected certificates
// escalate to a rerun-setup message after bounded retries.
#[test]
#[ignore = "needs live Samsung account handshake traffic"]
fn token_refresh_and_certificate_escalation_lifecycles() {}

// [FR-023 | FR-NFR 2.23 Scenario "Pairing failures back off"] Live run must
// observe: repeated pairing failures back off with growing delays and the
// failure is visible.
#[test]
#[ignore = "needs live pairing infrastructure"]
fn pairing_failures_back_off_with_growing_delays() {}
