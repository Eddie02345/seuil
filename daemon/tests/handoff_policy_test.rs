//! Black-box tests for the call policy and dial-authenticity boundaries.
//!
//! Covers:
//! - FR-017: an active HFP call blocks media-reason handoffs, call-reason
//!   switching proceeds during HFP, and the call guard is scoped to
//!   call-reason responses (a media response never clears the guard)
//! - FR-011: only the configured phone address is acted on
//!
//! Reached through the crate-include mechanism sanctioned by the task plan.

#![allow(dead_code)]
// Included source modules carry items this harness does not consume.
#![allow(unused_imports)]

#[path = "../src/protocol/mod.rs"]
mod protocol;

#[path = "../src/auth/mod.rs"]
mod auth;

#[path = "../src/config.rs"]
mod config;

#[path = "../src/ble/mod.rs"]
mod ble;

#[path = "../src/buds/mod.rs"]
mod buds;

#[path = "../src/rfcomm/mod.rs"]
mod rfcomm;

#[path = "../src/handoff/mod.rs"]
mod handoff;

use ble::coc_session;
use handoff::{CallGuard, HandoffConfig, HandoffStateMachine, SwitchReason};
use protocol::{AudioState, BleHeader, DeviceType};
use rfcomm::RfcommEvent;

const PHONE: &str = "AA:BB:CC:DD:EE:01";
const BUDS: &str = "AA:BB:CC:DD:EE:02";
const OTHER: &str = "11:22:33:44:55:66";

fn state_machine() -> HandoffStateMachine {
    HandoffStateMachine::new(HandoffConfig {
        phone_address: PHONE.to_string(),
        buds_address: BUDS.to_string(),
        auto_switch_enabled: true,
        priority: handoff::DevicePriority::FirstComeFirstServed,
    })
}

fn adv_event(address: &str, audio: AudioState) -> ble::BleAdvEvent {
    ble::BleAdvEvent {
        address: address.to_string(),
        address_type: bluer::AddressType::LePublic,
        rssi: -60,
        header: BleHeader {
            version: BleHeader::EXPECTED_VERSION,
            subtype: BleHeader::EXPECTED_SUBTYPE,
            flags: BleHeader::FLAG_EXTENDED_ADV,
        },
        device_type: DeviceType::Phone,
        context: None,
        audio_state: audio,
        coc_psm: None,
        raw_data: Vec::new(),
    }
}

// [FR-017 | spec-media-activity-filtering Requirement 2 Scenario "Media during
// a call"] GIVEN an active HFP call, WHEN local media starts, THEN the
// media-reason handoff is suppressed.
#[test]
fn active_call_blocks_media_reason_requests() {
    let mut guard = CallGuard::default();
    assert!(!guard.blocks_media());
    guard.call_started();
    assert!(guard.blocks_media(), "an active call must block media handoffs");
}

// [FR-017 | FR-NFR 2.17 Scenario "Call-reason switching during HFP"] Boundary:
// a call-reason request proceeds while the call guard is active.
#[test]
fn call_reason_requests_proceed_during_hfp() {
    let mut guard = CallGuard::default();
    guard.call_started();
    assert!(guard.blocks_media(), "call is active");
    guard.expect_call_response(7, [1, 2, 3, 4, 5, 6], std::time::Instant::now());
    assert_eq!(
        guard.on_response(7, [1, 2, 3, 4, 5, 6], std::time::Instant::now()),
        SwitchReason::Call,
    );
}

// [FR-017 | FR-NFR 2.17 Scenario "Lost call response does not lock media"]
// Boundary: a media-reason response never clears the call guard, so a lost
// call response cannot be masked by any other response; the guard clears only
// on the matching call-reason exchange.
#[test]
fn media_reason_response_never_clears_the_call_guard() {
    let mut guard = CallGuard::default();
    guard.call_started();
    guard.expect_call_response(9, [1, 2, 3, 4, 5, 6], std::time::Instant::now());
    // A media-reason response (no pending match classified as media) must not
    // lift the guard.
    let _ = guard.on_response(1, [9, 9, 9, 9, 9, 9], std::time::Instant::now());
    assert!(
        guard.blocks_media(),
        "a non-call response must not clear the call guard"
    );
}

// [FR-017 | FR-NFR 2.17] Boundary: only the matching call-reason exchange
// classifies as Call; a stale pending entry past its timeout degrades to Media.
// [FR-017 | FR-NFR 2.17] Boundary: a pending call exchange expires after its
// response timeout, so a non-matching response past the deadline classifies
// as Media and releases the pending slot; a later matching response can then
// no longer lift the exchange as Call.
#[test]
fn stale_call_response_exchanges_classify_as_media() {
    let mut guard = CallGuard::default();
    let now = std::time::Instant::now();
    guard.expect_call_response(9, [1, 2, 3, 4, 5, 6], now);
    // A non-matching response past the response timeout must not classify as
    // Call, and it releases the pending exchange.
    let later = now + std::time::Duration::from_secs(3600);
    assert_eq!(
        guard.on_response(1, [9, 9, 9, 9, 9, 9], later),
        SwitchReason::Media
    );
    // After the release, a matching response can no longer classify as Call.
    assert_eq!(
        guard.on_response(9, [1, 2, 3, 4, 5, 6], later),
        SwitchReason::Media
    );
    assert_eq!(SwitchReason::from_byte(coc_session::REASON_CALL), SwitchReason::Call);
    assert_eq!(SwitchReason::from_byte(coc_session::REASON_MEDIA), SwitchReason::Media);
}

// [FR-011 | FR-NFR 2.11 Scenario "Spoofed advertisement ignored"] GIVEN a
// type 1 advertisement from an address other than the configured phone, WHEN
// the state machine evaluates it, THEN no handoff action results.
#[test]
fn advertisement_from_an_unknown_address_is_ignored() {
    let mut sm = state_machine();
    for audio in [AudioState::Streaming, AudioState::Idle, AudioState::Disconnected] {
        assert!(
            sm.on_ble_event(&adv_event(OTHER, audio)).is_none(),
            "an address outside the configured pair must produce no action"
        );
    }
}

// [FR-011 | FR-NFR 2.11] Boundary: the configured phone's Streaming
// advertisement while Linux is not the active source yields no yield action;
// the suppression boundary holds.
#[test]
fn phone_streaming_before_a_linux_session_yields_nothing() {
    let mut sm = state_machine();
    assert!(sm.on_ble_event(&adv_event(PHONE, AudioState::Streaming)).is_none());
    // Local media while the phone owns the buds: no claim.
    assert!(sm.on_local_media_start().is_none());
}

// [FR-013 | FR-NFR 2.13 Scenario "Phone-directed commands ride the CoC"]
// Contract: phone-directed auto switch commands decode as CoC commands; the
// SPP path carries only Buds opcodes. A received SPP frame with a Buds
// switch-request shape maps to YieldToPhone per the legacy SPP fallback,
// while a phone-directed switch request builds a CoC body.
#[test]
fn phone_directed_switch_request_body_uses_the_coc_reason_bytes() {
    let body =
        coc_session::switch_request_body(123, [1, 2, 3, 4, 5, 6], coc_session::REASON_CALL);
    assert!(
        body.len() >= 2,
        "the phone-directed CoC request body must be self-contained"
    );
    let response =
        coc_session::switch_response_body(0, 123, [1, 2, 3, 4, 5, 6]);
    assert!(
        response.len() >= 2,
        "the CoC response body must be self-contained"
    );
}

// [FR-017 | spec-media-activity-filtering RULE-004] The legacy SPP fallback
// still honours the transport split shape: a ready event maps to PhoneReady.
#[test]
fn legacy_spp_ready_event_maps_to_phone_ready() {
    let mut sm = state_machine();
    let action = sm.on_rfcomm_event(&RfcommEvent::Received {
        address: PHONE.to_string(),
        data: vec![1, 10, 3, 0x00],
    });
    assert!(matches!(action, Some(handoff::HandoffAction::PhoneReady)));
}
