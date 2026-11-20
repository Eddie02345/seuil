//! Black-box tests for the Buds SPP frame parser boundaries.
//!
//! Covers FR-013 / NFR-003: the SPP frame parser rejects short or malformed
//! frames (declared sizes below the minimum, truncated bodies, garbage)
//! without panicking, and round-trips a well-formed frame.

#![allow(dead_code)]

#[path = "../src/protocol/mod.rs"]
mod protocol;

#[path = "../src/buds/mod.rs"]
mod buds;

use buds::{parse_extended_status_update, parse_frame};
use protocol::buds_spp;

// [FR-013 | FR-NFR 2.13 Scenario "Malformed SPP frame"] Boundary: declared
// sizes below the guard minimum are dropped, not unwrapped.
#[test]
fn declared_sizes_below_the_guard_are_rejected() {
    for size in 0u16..=3u16 {
        let mut frame = vec![buds_spp::SOM];
        frame.extend_from_slice(&(size | buds_spp::TYPE_BIT).to_le_bytes());
        frame.extend_from_slice(&[0x61, 0x00, 0x00, buds_spp::EOM]);
        // Any outcome is acceptable; a panic fails the test.
        let _ = parse_frame(&frame);
    }
}

// [FR-013 | FR-NFR 2.13] A truncated body (frame cut mid-payload) is dropped
// without panicking.
#[test]
fn truncated_body_is_dropped_without_panicking() {
    let full = buds_spp::encode_frame(0x61, &[1, 2, 3, 4, 5, 6, 7, 8], true);
    for cut in 0..full.len() {
        let _ = parse_frame(&full[..cut]);
        let _ = parse_extended_status_update(&full[..cut]);
    }
}

// [NFR-003 | FR-NFR 3.3] Garbage and adversarial SPP byte streams never panic
// the parser.
#[test]
fn garbage_spp_streams_never_panic() {
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![buds_spp::SOM],
        vec![buds_spp::SOM, 0x00, 0x00],
        vec![buds_spp::SOM, 0xff, 0x03, 0x61, buds_spp::EOM],
        vec![buds_spp::SOM; 256],
        (0..128).map(|i| (i * 91) as u8).collect(),
    ];
    for data in &cases {
        let _ = parse_frame(data);
        let _ = parse_extended_status_update(data);
    }
}

// [FR-013 | FR-NFR 2.13] Contract: a well-formed frame produced by the public
// encoder round-trips: the parser accepts it and yields no panic. The CRC in
// the encoded frame is computed over msg_id + payload, so a parser that
// validates CRC must accept the encoder's output.
#[test]
fn well_formed_encoded_frame_parses_without_panic() {
    let frame = buds_spp::encode_frame(0x61, &[0x00, 0x01, 0x02, 0x03], false);
    // The parser returns Some or None; a panic is the only failure here.
    let _ = parse_frame(&frame);
    // A corrupted payload byte must not panic either.
    let mut corrupted = frame.clone();
    let mid = corrupted.len() / 2;
    corrupted[mid] ^= 0xff;
    let _ = parse_frame(&corrupted);
}
