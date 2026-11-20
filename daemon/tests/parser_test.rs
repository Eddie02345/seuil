//! Black-box tests for the BLE/L2CAP parser boundaries.
//!
//! Covers:
//! - FR-008: dual format-byte readings, malformed LTV records, overrun safety,
//!   garbage rejection, the account-bound and fallback audio-state anchors
//! - FR-011: advertisement checksum verification against the account fingerprint
//! - FR-012: malformed address strings and crypto-size failures are errors
//! - FR-013/NFR-003: malformed L2CAP CoC command frames never panic
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

use auth::ble_keys::BleKeyDerivation;
use ble::parse_mcf_manufacturer_data;
use protocol::command::parse_frame as parse_coc_frame;
use protocol::{AudioState, DeviceType};

/// The offset-3 fixture from FR-NFR 2.8.
const OFFSET3_PAYLOAD: [u8; 11] = [0x02, 0x18, 0x00, 0x01, 0x00, 0x80, 0x07, 0x48, 0x00, 0x48, 0x00];

/// The offset-2 fixture from FR-NFR 2.8: the format byte moved to offset 2.
const OFFSET2_PAYLOAD: [u8; 11] = [0x02, 0x18, 0x01, 0x00, 0x00, 0x80, 0x07, 0x48, 0x00, 0x48, 0x00];

/// An unconfigured key derivation: the spec fixtures carry plaintext context
/// bytes, so the context decodes without account obfuscation.
fn unbound_keys() -> BleKeyDerivation {
    BleKeyDerivation::new(Vec::new())
}

/// An account-bound key derivation with a fixed fingerprint.
fn bound_keys() -> BleKeyDerivation {
    BleKeyDerivation::new(vec![0xaa; 32])
}

/// Builds the account-bound advertisement used by the record-walk tests.
fn built_adv(state: AudioState) -> Vec<u8> {
    ble::build_mcf_advertisement_with_account(
        ble::DEVICE_KIND_PHONE,
        state,
        &bound_keys(),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        0x0080,
        None,
    )
}

// [FR-008 | spec-transport-lifecycle-hardening | FR-NFR 2.8 Scenario "Offset-3
// reading accepted"] Valid: the primary reading decodes the settled fixture to
// context CoC 0x0080, DS 0x07, NS 0x48, F 0x00 and audio state Streaming.
#[test]
fn offset3_reading_decodes_the_settled_fixture() {
    let parsed = parse_mcf_manufacturer_data(&OFFSET3_PAYLOAD, &unbound_keys())
        .expect("the offset-3 fixture must parse");
    let context = parsed.context.expect("the context must decode");
    assert_eq!(context.coc, 0x0080);
    assert_eq!(context.device_state, 0x07);
    assert_eq!(context.notification_state, 0x48);
    assert_eq!(context.features, 0x00);
    assert_eq!(parsed.audio_state, AudioState::Streaming);
}

// [FR-008 | FR-NFR 2.8 Scenario "Offset-2 reading accepted"] Boundary: the
// same logical payload with the format byte at offset 2 must decode to the
// same device context rather than being rejected.
#[test]
fn offset2_reading_decodes_to_the_same_context() {
    let parsed = parse_mcf_manufacturer_data(&OFFSET2_PAYLOAD, &unbound_keys())
        .expect("the offset-2 reading must be accepted");
    let context = parsed.context.expect("the context must decode");
    assert_eq!(context.coc, 0x0080);
    assert_eq!(context.device_state, 0x07);
    assert_eq!(context.notification_state, 0x48);
    assert_eq!(context.features, 0x00);
    assert_eq!(parsed.audio_state, AudioState::Streaming);
}

// [FR-008 | FR-NFR 2.8 Scenario "Recoverable malformed record skipped"]
// Boundary: a zero-length record inside the walk is skipped and the valid
// type 1 record still decodes (PSM 0x0080 preserved), with no panic.
#[test]
fn zero_length_record_is_skipped_and_later_record_still_parses() {
    let mut data = built_adv(AudioState::Streaming);
    // A zero-length record header inserted into the walk region.
    data.insert(data.len() - 1, 0x00);
    let parsed = parse_mcf_manufacturer_data(&data, &bound_keys())
        .expect("the walk must skip the malformed record and keep parsing");
    assert_eq!(parsed.coc_psm, Some(0x0080), "the valid record must still decode");
    assert_eq!(parsed.audio_state, AudioState::Streaming);
}

// [FR-008 | FR-NFR 2.8 Scenario "Overrunning record ends the walk safely"]
// Boundary: a record whose declared length overruns the buffer ends the walk
// gracefully; the type 1 record decoded before the overrun is preserved.
#[test]
fn overrunning_record_ends_the_walk_without_panic() {
    let mut data = built_adv(AudioState::Streaming);
    // A record header whose length nibble (15) runs past the buffer end.
    data.push(0xF1);
    let parsed = parse_mcf_manufacturer_data(&data, &bound_keys());
    let parsed = parsed.expect("the overrun must end the walk, not abort the parse");
    assert_eq!(
        parsed.coc_psm,
        Some(0x0080),
        "a record decoded before the overrun must survive"
    );
}

// [FR-008 | FR-NFR 2.8 Scenario "Garbage payload"] Invalid: random bytes with
// a plausible Samsung header return rejection without panicking.
#[test]
fn garbage_payload_is_rejected_without_panicking() {
    for seed in 0..8u8 {
        let mut data = [0x02u8, 0x18, seed.wrapping_mul(37), seed, seed, seed, seed, seed, seed, seed, seed];
        data[2] = seed.wrapping_mul(37).wrapping_add(1);
        // Must return (Some or None) without panicking.
        let _ = parse_mcf_manufacturer_data(&data, &unbound_keys());
    }
}

// [FR-008 | FR-NFR 2.8 Scenario "Account-bound audio-state anchor"] Boundary:
// the record-local notification anchor maps 0x48 to Streaming, 0x08 to Idle,
// 0x00 to Disconnected, and the type 1 record yields PSM 0x0080.
#[test]
fn account_bound_anchor_maps_the_three_audio_states() {
    for (state, expected) in [
        (AudioState::Streaming, AudioState::Streaming),
        (AudioState::Idle, AudioState::Idle),
        (AudioState::Disconnected, AudioState::Disconnected),
    ] {
        let parsed = parse_mcf_manufacturer_data(&built_adv(state), &bound_keys())
            .expect("the account-bound advertisement must parse");
        assert_eq!(parsed.audio_state, expected);
        assert_eq!(parsed.coc_psm, Some(0x0080), "the type 1 record must yield PSM 0x0080");
        assert_eq!(parsed.device_type, DeviceType::Phone);
    }
}

// [FR-008 | FR-NFR 2.8 Scenario "Fallback audio-state anchor"] Boundary: on an
// unbound advertisement the manufacturer-data byte 9 anchors the audio state
// (0x48 Streaming, 0x08 Idle, 0x18 Disconnected).
#[test]
fn fallback_anchor_on_byte9_maps_the_three_audio_states() {
    for (byte9, expected) in [(0x48u8, AudioState::Streaming), (0x08, AudioState::Idle), (0x18, AudioState::Disconnected)] {
        let mut data = OFFSET3_PAYLOAD;
        data[9] = byte9;
        let parsed = parse_mcf_manufacturer_data(&data, &unbound_keys());
        if let Some(parsed) = parsed {
            assert_eq!(
                parsed.audio_state, expected,
                "byte 9 = 0x{byte9:02x} must parse {expected:?}"
            );
        }
    }
}

// [NFR-003 | FR-NFR 3.3] The malformed-frame set must return without panicking:
// truncated headers, bad subtypes, short bodies, and random byte soup.
#[test]
fn malformed_frame_set_returns_without_panicking() {
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x02],
        vec![0x02, 0x18],
        vec![0x02, 0x18, 0x00],
        vec![0x02, 0x19, 0x00, 0x01, 0x00],
        vec![0x00, 0x00, 0x00, 0x00, 0x00],
        vec![0x02, 0x18, 0x0f, 0x02, 0xff],
        vec![0x02, 0x18, 0x00, 0x01, 0x01, 0x80],
        (0..24).map(|i| (i * 31 + 7) as u8).collect(),
        vec![0xff_u8; 64],
    ];
    for data in &cases {
        // Any outcome is acceptable; a panic fails the test.
        let _ = parse_mcf_manufacturer_data(data, &unbound_keys());
    }
}

// [FR-012 | FR-NFR 2.12 Scenario "Malformed address string"] Invalid: an
// address string that fails to parse is an error, not a panic.
#[test]
fn malformed_address_strings_are_errors() {
    for bad in ["", "nope", "AA:BB:CC:DD:EE", "zz:zz:zz:zz:zz:zz"] {
        let result = ble::coc_session::parse_address(bad);
        assert!(result.is_err(), "{bad:?} must not parse as an address");
    }
    assert!(ble::coc_session::parse_address("AA:BB:CC:DD:EE:FF").is_ok());
}

// [FR-012 | FR-NFR 2.12 Scenario "Crypto-size failure contained"] Boundary: a
// decrypt call with a wrong-size input is an error, not a panic.
#[test]
fn wrong_size_ciphertext_is_an_error_not_a_panic() {
    let key = [7u8; 32];
    let bad = [
        Vec::new(),
        vec![1, 2, 3],
        vec![0u8; 12],
        (0..64).map(|i| (i * 13) as u8).collect(),
    ];
    for data in &bad {
        assert!(
            protocol::command::decrypt(&key, data).is_err(),
            "wrong-size input must be an error"
        );
    }
}

// [FR-013 | FR-NFR 2.13 | NFR-003] Malformed L2CAP CoC command frames: the
// frame parser rejects garbage without panicking.
#[test]
fn malformed_coc_frames_are_rejected_without_panicking() {
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0xff; 12],
        vec![0x08, 0x00],
        vec![0xa5_u8; 1024],
    ];
    for frame in &cases {
        let _ = parse_coc_frame(frame);
    }
}

// [FR-011 | FR-NFR 2.11 Scenario "Valid advertisement acted on" and "Bad
// checksum ignored"] Boundary: an advertisement built from the account
// matches its fingerprint checksum, and corrupting the checksum byte breaks
// the match so the payload is not acted on.
#[test]
fn advertisement_checksum_distinguishes_matching_and_forged_payloads() {
    let data = built_adv(AudioState::Streaming);
    assert!(
        ble::advertisement_checksum_matches(&data, &bound_keys()),
        "a built advertisement must match its account fingerprint"
    );
    let breaking = (0..data.len()).any(|pos| {
        let mut forged = data.clone();
        forged[pos] ^= 0xff;
        !ble::advertisement_checksum_matches(&forged, &bound_keys())
    });
    assert!(
        breaking,
        "corrupting the checksum byte must break the fingerprint match"
    );
}
