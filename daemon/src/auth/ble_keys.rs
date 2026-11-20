//! Derivation of the Samsung MCF BLE account keys.
//!
//! The phone advertises a rotating account identity inside the manufacturer
//! specific data (Company ID `0x0075`). The identity is not cryptographic: a
//! [SHA-256] table is built from an account fingerprint, bit positions are
//! selected from additional SHA-256 rounds, and the result is XOR-obfuscated
//! into the advertisement. This module reimplements the derivation observed on the
//! wire:
//!
//! | Rust method | Role |
//! |---|---|
//! | `build_sha256_table` | SHA-256 table from the fingerprint |
//! | `update_rotation` | Advance the 12-hour bucket |
//! | `build_filter` | 5-byte advertisement filter |
//! | `build_mask` | Advertising mask |
//! | `compute_account_hash` | 5-byte account hash |
//! | `compute_ex_hash` | 8-byte extended hash |
//! | `xor_table` | Obfuscation schedule |
//! | `apply_bit_select` | SHA-256 bit selection |
//! | `set_bit` | Bit insertion |
//!
//! The account fingerprint comes from the SCPM keystore and is supplied by the
//! caller; this module does not perform OAuth.

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// XOR constant applied to the 8-byte extended account hash.
pub const EX_HASH_CONSTANT: [u8; 8] = [0xC2, 0x09, 0xD4, 0x17, 0xF5, 0xA3, 0x6B, 0xE0];

/// Account identity rotation period, 12 hours.
pub const ROTATION_PERIOD_MS: u128 = 43_200_000;

/// Length of the SHA-256 table used for payload obfuscation.
const SHA256_LEN: usize = 32;
/// Length of the rotating account hash.
const ACCOUNT_HASH_LEN: usize = 5;
/// Length of the extended account hash.
const EX_HASH_LEN: usize = 8;
/// Bit-selection rounds per fingerprint rotation, 5-byte mask.
const FILTER_SELECT_ROUNDS: usize = 9;
/// Bit-selection rounds per fingerprint rotation, 8-byte mask.
const EX_HASH_SELECT_ROUNDS: usize = 6;
/// Bit flips applied to the advertising mask.
const MASK_FLIPS: usize = 9;
/// Bit flips applied to the advertising extended hash.
const EX_HASH_FLIPS: usize = 6;

/// Which side of the protocol this instance derives keys for.
///
/// The phone distinguishes advertising from scanning: the advertising instance
/// rotates the
/// fingerprint twice per bucket and adds random mask bits, the scanning
/// instance uses a single rotation and no random bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountRole {
    /// We advertise the account identity.
    Advertise,
    /// We scan advertisements produced by the phone.
    Scan,
}

impl AccountRole {
    /// Bucket offset added before division.
    fn rotation_offset_ms(self) -> u64 {
        match self {
            AccountRole::Advertise => 0,
            AccountRole::Scan => 21_600_000,
        }
    }

    /// Number of fingerprint rotations folded into the mask.
    fn fingerprint_rounds(self) -> usize {
        match self {
            AccountRole::Advertise => 2,
            AccountRole::Scan => 1,
        }
    }

    /// Number of random bit-flip passes.
    fn random_flip_rounds(self) -> usize {
        match self {
            AccountRole::Advertise => 1,
            AccountRole::Scan => 0,
        }
    }
}

/// Rotating account keys derived from a known account fingerprint.
#[derive(Debug, Clone)]
pub struct BleKeyDerivation {
    /// Keystore value the phone derived from the Samsung account.
    account_fingerprint: Vec<u8>,
    /// `SHA-256(account_fingerprint)`, also the obfuscation table.
    sha256_table: [u8; SHA256_LEN],
    /// 12-hour rotation bucket.
    rotation_bucket: u32,
    /// 5-byte rotating account hash advertised in the account LTV.
    account_hash_5: [u8; ACCOUNT_HASH_LEN],
    /// 8-byte extended account hash used for background matching.
    ex_hash_8: [u8; EX_HASH_LEN],
    /// XOR checksum over the rotated SHA-256 table.
    fingerprint_checksum: u8,
    /// Advertising or scanning side.
    role: AccountRole,
}

impl BleKeyDerivation {
    /// Derive the advertising-side keys for a known account fingerprint.
    ///
    /// An empty fingerprint yields an unconfigured instance: [`Self::is_configured`]
    /// returns `false`, the hashes are zero, and [`Self::obfuscate`] leaves the
    /// payload unchanged. The daemon passes the SCPM fingerprint once the
    /// account is linked.
    pub fn new(account_fingerprint: Vec<u8>) -> Self {
        Self::with_role(account_fingerprint, AccountRole::Advertise)
    }

    /// Derive keys for an explicit protocol role.
    pub fn with_role(account_fingerprint: Vec<u8>, role: AccountRole) -> Self {
        let mut keys = Self {
            account_fingerprint,
            sha256_table: [0u8; SHA256_LEN],
            rotation_bucket: 0,
            account_hash_5: [0u8; ACCOUNT_HASH_LEN],
            ex_hash_8: [0u8; EX_HASH_LEN],
            fingerprint_checksum: 0,
            role,
        };
        keys.build_sha256_table();
        keys.update_rotation();
        keys.rebuild();
        keys
    }

    /// Recompute the keys when the 12-hour rotation bucket changed.
    ///
    /// Returns `true` when the bucket changed and the keys were rebuilt. Call
    /// this from the advertisement refresh timer.
    pub fn refresh(&mut self) -> bool {
        if !self.update_rotation() {
            return false;
        }
        self.rebuild();
        true
    }

    /// `SHA-256(account_fingerprint)`.
    fn build_sha256_table(&mut self) {
        self.sha256_table = sha256(&self.account_fingerprint);
    }

    /// Advance to the current 12-hour bucket.
    ///
    /// Returns whether the bucket changed.
    fn update_rotation(&mut self) -> bool {
        let bucket = rotation_bucket_at(unix_time_ms(), self.role.rotation_offset_ms());
        let changed = bucket != self.rotation_bucket;
        self.rotation_bucket = bucket;
        changed
    }

    /// Build the deterministic 5-byte filter.
    ///
    /// Walks all 40 bit positions in order and keeps a bit when the fingerprint
    /// byte mapped to that position passes a shrinking reservoir-sampling test.
    /// Exactly 20 of the 40 bits end up set.
    fn build_filter(&self) -> [u8; ACCOUNT_HASH_LEN] {
        let mut out = [0u8; ACCOUNT_HASH_LEN];
        if self.account_fingerprint.is_empty() {
            return out;
        }

        let bits = ACCOUNT_HASH_LEN * 8;
        let mut quota = bits as i32 / 2;
        for idx in 0..bits {
            let byte = self.account_fingerprint[idx % self.account_fingerprint.len()] as u32;
            if ((byte % (bits - idx) as u32) as i32) < quota {
                set_bit(&mut out, idx);
                quota -= 1;
            }
        }
        out
    }

    /// Build the rotating 5-byte mask with SHA-256 bit selection
    ///.
    fn build_mask(&self) -> [u8; ACCOUNT_HASH_LEN] {
        let mut out = [0u8; ACCOUNT_HASH_LEN];
        if !self.is_configured() {
            return out;
        }
        for round in 0..self.role.fingerprint_rounds() {
            let seed = rotated(
                &self.account_fingerprint,
                self.rotation_bucket.wrapping_add(round as u32),
            );
            apply_bit_select(&seed, &mut out, FILTER_SELECT_ROUNDS);
        }
        out
    }

    /// Combine the flipped mask with the filter.
    fn compute_account_hash(&mut self) {
        let mut mask = self.build_mask();
        self.flip_random_bits(&mut mask);
        let filter = self.build_filter();
        for (idx, out) in self.account_hash_5.iter_mut().enumerate() {
            *out = mask[idx] ^ filter[idx];
        }
    }

    /// Compute the 8-byte extended hash.
    fn compute_ex_hash(&mut self) {
        let mut mask = [0u8; EX_HASH_LEN];
        if !self.is_configured() {
            self.ex_hash_8 = [0u8; EX_HASH_LEN];
            return;
        }
        for round in 0..self.role.fingerprint_rounds() {
            let seed = rotated(
                &self.account_fingerprint,
                self.rotation_bucket.wrapping_add(round as u32),
            );
            apply_bit_select(&seed, &mut mask, EX_HASH_SELECT_ROUNDS);
        }
        self.flip_random_bits(&mut mask);
        for (idx, out) in self.ex_hash_8.iter_mut().enumerate() {
            *out = mask[idx] ^ EX_HASH_CONSTANT[idx];
        }
    }

    /// XOR checksum exposed in the advertisement.
    ///
    /// Only the advertising role publishes it.
    fn compute_fingerprint_checksum(&self) -> u8 {
        self.checksum_at(self.rotation_bucket)
    }

    /// XOR of ten table bytes selected backwards from `rotation`
    /// (`BluetoothChannel.swift:24`).
    fn checksum_at(&self, rotation: u32) -> u8 {
        let table = &self.sha256_table;
        let mut checksum = 0u8;
        for index in 0..10u32 {
            let idx = ((index as i32 - rotation as i32) % 32 + 32) % 32;
            checksum ^= table[idx as usize];
        }
        checksum
    }

    /// Set random bits in a mask, matching the phone's rotation.
    ///
    /// The phone uses a non-cryptographic PRNG, so the exact positions are
    /// not reproducible across processes. A SplitMix64 stream seeded from the
    /// SHA-256 table and rotation keeps the output stable for one fingerprint
    /// and bucket while preserving the noise the phone expects.
    fn flip_random_bits(&self, mask: &mut [u8]) {
        let flips_per_round = match mask.len() {
            ACCOUNT_HASH_LEN => MASK_FLIPS,
            _ => EX_HASH_FLIPS,
        };
        let flips = self.role.random_flip_rounds() * flips_per_round;
        if flips == 0 || mask.is_empty() {
            return;
        }

        let mut state = self.random_seed();
        let bits = (mask.len() * 8) as u64;
        for _ in 0..flips {
            let idx = (next_u64(&mut state) % bits) as usize;
            set_bit(mask, idx);
        }
    }

    /// Seed for the deterministic mask noise.
    fn random_seed(&self) -> u64 {
        let mut head = [0u8; 8];
        head.copy_from_slice(&self.sha256_table[..8]);
        u64::from_be_bytes(head) ^ (self.rotation_bucket as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
    }

    /// Rebuild every derived value for the current fingerprint and bucket.
    fn rebuild(&mut self) {
        if !self.is_configured() {
            self.account_hash_5 = [0u8; ACCOUNT_HASH_LEN];
            self.ex_hash_8 = [0u8; EX_HASH_LEN];
            self.fingerprint_checksum = 0;
            return;
        }
        self.compute_account_hash();
        self.compute_ex_hash();
        self.fingerprint_checksum = match self.role {
            AccountRole::Advertise => self.compute_fingerprint_checksum(),
            AccountRole::Scan => 0,
        };
    }

    /// Apply XOR obfuscation to an outbound advertisement.
    ///
    /// `header_bytes` is the packet slice the phone XORs to pick the
    /// table offset: `payload[4..9]` for the short format, `payload[5..13]` for
    /// the extended formats. If its length does not match the packet layout the
    /// canonical slice is used instead.
    #[allow(dead_code)] // Symmetric helper exposed for outbound advertisements.
    pub fn obfuscate(&self, payload: &mut [u8], header_bytes: &[u8]) {
        self.xor_table(payload, header_bytes);
    }

    /// Reverse [`Self::obfuscate`]. XOR is symmetric.
    ///
    /// [FR-008] Returns whether the payload had a known layout and was
    /// deobfuscated, so callers never parse an untouched payload as if the
    /// obfuscation had been removed.
    pub fn deobfuscate(&self, payload: &mut [u8], header_bytes: &[u8]) -> bool {
        self.xor_table(payload, header_bytes)
    }

    /// XOR the SHA-256 table into the payload from the account LTV onward.
    ///
    /// Returns `false` when no key is configured or the packet layout is
    /// unknown, leaving the payload untouched.
    fn xor_table(&self, payload: &mut [u8], header_bytes: &[u8]) -> bool {
        if !self.is_configured() {
            return false;
        }
        let Some((header_start, header_len, xor_start)) = xor_layout(payload) else {
            return false;
        };

        let mut offset = 0u8;
        if header_bytes.len() == header_len {
            for &byte in header_bytes {
                offset ^= byte;
            }
        } else {
            for &byte in &payload[header_start..header_start + header_len] {
                offset ^= byte;
            }
        }

        let pad = (offset as usize) % self.sha256_table.len();
        for (idx, byte) in payload.iter_mut().enumerate().skip(xor_start) {
            *byte ^= self.sha256_table[(pad + idx) % self.sha256_table.len()];
        }
        true
    }

    /// Whether a fingerprint was supplied.
    pub fn is_configured(&self) -> bool {
        !self.account_fingerprint.is_empty()
    }

    /// 5-byte account hash advertised in the account LTV.
    #[allow(dead_code)] // Exposed for callers that publish the account hash.
    pub fn account_hash(&self) -> &[u8; ACCOUNT_HASH_LEN] {
        &self.account_hash_5
    }

    /// 8-byte extended account hash.
    pub fn ex_hash(&self) -> &[u8; EX_HASH_LEN] {
        &self.ex_hash_8
    }

    /// SHA-256 obfuscation table derived from the account fingerprint.
    pub fn sha256_table(&self) -> &[u8; SHA256_LEN] {
        &self.sha256_table
    }

    /// XOR checksum of the rotated SHA-256 table, `0` for the scanning role.
    pub fn fingerprint_checksum(&self) -> u8 {
        self.fingerprint_checksum
    }

    /// Whether `byte` matches the checksum for the current or previous bucket.
    ///
    /// The phone accepts an advertisement from either bucket while the 12-hour
    /// rotation boundary passes (`BluetoothChannel.swift:24`).
    pub fn checksum_matches(&self, byte: u8) -> bool {
        let rotation = self.rotation_bucket;
        byte == self.checksum_at(rotation) || byte == self.checksum_at(rotation.wrapping_sub(1))
    }
}

/// Packet layout: `(header start, header length, XOR start)`.
///
/// Returns `None` for packets the phone rejects.
fn xor_layout(payload: &[u8]) -> Option<(usize, usize, usize)> {
    if payload.len() < 14 {
        return None;
    }

    let flags = payload[3];
    if flags & 0x80 == 0 {
        // Extended header (pa.a.c()): at least 21 bytes.
        if payload.len() < 21 {
            return None;
        }
        let xor_start = if flags & 0x40 != 0 { 13 } else { 16 };
        Some((5, 8, xor_start))
    } else {
        // Short header; a secondary block raises the minimum to 18 bytes.
        if flags & 0x40 != 0 && payload.len() < 18 {
            return None;
        }
        Some((4, 5, 9))
    }
}

/// Apply `rounds` SHA-256 bit selections into `out`.
fn apply_bit_select(seed: &[u8], out: &mut [u8], rounds: usize) {
    if seed.is_empty() || out.is_empty() {
        return;
    }

    let mut state = seed.to_vec();
    let mut acc = 0i64;
    let bits = (out.len() * 8) as i64;
    for _ in 0..rounds {
        for byte in sha256(&state) {
            acc += byte as i8 as i64;
        }
        let idx = (acc.abs() % bits) as usize;
        set_bit(out, idx);
        state[0] = state[0].wrapping_add(1);
    }
}

/// Collect `rounds` bit selections into a fresh array.
#[cfg(test)]
fn bit_select(seed: &[u8], nbytes: usize, rounds: usize) -> Vec<u8> {
    let mut out = vec![0u8; nbytes];
    apply_bit_select(seed, &mut out, rounds);
    out
}

/// Set bit `idx`, numbering bytes from the end of the array.
fn set_bit(out: &mut [u8], idx: usize) {
    if out.is_empty() || idx >= out.len() * 8 {
        return;
    }
    let byte = out.len() - (idx / 8) - 1;
    out[byte] |= 1 << (idx % 8);
}

/// Rotate an array so element `i` lands at `(i + amount) % len`.
fn rotated(src: &[u8], amount: u32) -> Vec<u8> {
    let len = src.len();
    if len == 0 {
        return Vec::new();
    }
    let shift = amount as usize % len;
    let mut out = vec![0u8; len];
    for (idx, &byte) in src.iter().enumerate() {
        out[(idx + shift) % len] = byte;
    }
    out
}

/// 12-hour bucket for a timestamp, including the per-role offset.
fn rotation_bucket_at(now_ms: u64, offset_ms: u64) -> u32 {
    ((now_ms as u128 + offset_ms as u128) / ROTATION_PERIOD_MS) as u32
}

/// Current wall-clock time in milliseconds since the Unix epoch.
fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// SHA-256 digest as a fixed-size array.
fn sha256(data: &[u8]) -> [u8; SHA256_LEN] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; SHA256_LEN];
    out.copy_from_slice(&digest);
    out
}

/// SplitMix64 step, used for mask noise.
fn next_u64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

/// Reference vectors come from a standalone Java harness that mirrors the
/// observed derivation using SHA-256, so the expected bytes do
/// not depend on this Rust implementation.
#[cfg(test)]
mod tests {
    use super::*;

    const FINGERPRINT_16: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    const FINGERPRINT_32: [u8; 32] = [
        0x01, 0x08, 0x0F, 0x16, 0x1D, 0x24, 0x2B, 0x32, 0x39, 0x40, 0x47, 0x4E, 0x55, 0x5C, 0x63,
        0x6A, 0x71, 0x78, 0x7F, 0x86, 0x8D, 0x94, 0x9B, 0xA2, 0xA9, 0xB0, 0xB7, 0xBE, 0xC5, 0xCC,
        0xD3, 0xDA,
    ];
    const ROTATION: u32 = 41_234;

    fn keys_at(fingerprint: &[u8], role: AccountRole, rotation: u32) -> BleKeyDerivation {
        let mut keys = BleKeyDerivation::with_role(fingerprint.to_vec(), role);
        keys.rotation_bucket = rotation;
        keys.rebuild();
        keys
    }

    fn hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    #[test]
    fn sha256_table_matches_reference() {
        let keys = keys_at(&FINGERPRINT_16, AccountRole::Scan, ROTATION);
        assert_eq!(
            hex(&keys.sha256_table),
            "a8faed6abbf35c12a4b26e40f6feb19d736d90045c83b9f9a31f638d323e6811"
        );
    }

    #[test]
    fn filter_matches_reference() {
        let keys = keys_at(&FINGERPRINT_16, AccountRole::Scan, ROTATION);
        assert_eq!(hex(&keys.build_filter()), "193681f96b");
    }

    #[test]
    fn mask_matches_reference() {
        let keys = keys_at(&FINGERPRINT_16, AccountRole::Advertise, ROTATION);
        assert_eq!(hex(&keys.build_mask()), "30480d5730");
    }

    #[test]
    fn scan_keys_match_reference() {
        let keys = keys_at(&FINGERPRINT_16, AccountRole::Scan, ROTATION);
        assert_eq!(hex(keys.account_hash()), "293688ed4b");
        assert_eq!(hex(keys.ex_hash()), "f218c017f5a36be0");
    }

    #[test]
    fn checksum_matches_reference() {
        let keys = keys_at(&FINGERPRINT_16, AccountRole::Advertise, ROTATION);
        assert_eq!(keys.fingerprint_checksum(), 0x39);

        let keys = keys_at(&FINGERPRINT_32, AccountRole::Advertise, ROTATION);
        assert_eq!(keys.fingerprint_checksum(), 0xCE);
    }

    #[test]
    fn scan_role_publishes_no_checksum() {
        let keys = keys_at(&FINGERPRINT_16, AccountRole::Scan, ROTATION);
        assert_eq!(keys.fingerprint_checksum(), 0);
    }

    #[test]
    fn checksum_matches_current_and_previous_bucket() {
        let keys = keys_at(&FINGERPRINT_16, AccountRole::Advertise, ROTATION);
        let previous = keys_at(&FINGERPRINT_16, AccountRole::Advertise, ROTATION - 1);

        assert!(keys.checksum_matches(keys.fingerprint_checksum()));
        assert!(keys.checksum_matches(previous.fingerprint_checksum()));
        assert!(!keys.checksum_matches(keys.fingerprint_checksum() ^ 0xFF));
    }

    #[test]
    fn bit_select_matches_reference() {
        let seed = rotated(&FINGERPRINT_16, ROTATION);
        assert_eq!(hex(&bit_select(&seed, 5, 9)), "3000091420");
        assert_eq!(hex(&bit_select(&seed, 8, 6)), "3011140000000000");
    }

    #[test]
    fn rotation_bucket_calculation() {
        assert_eq!(rotation_bucket_at(0, 0), 0);
        assert_eq!(rotation_bucket_at(43_199_999, 0), 0);
        assert_eq!(rotation_bucket_at(43_200_000, 0), 1);
        assert_eq!(rotation_bucket_at(86_400_000, 0), 2);
        assert_eq!(rotation_bucket_at(1_700_000_000_000, 0), 39_351);
        // Scanning adds a 6-hour offset before bucketing.
        assert_eq!(rotation_bucket_at(21_599_999, 21_600_000), 0);
        assert_eq!(rotation_bucket_at(21_600_000, 21_600_000), 1);
    }

    #[test]
    fn rotation_change_rebuilds_keys() {
        let first = keys_at(&FINGERPRINT_16, AccountRole::Scan, ROTATION);
        let next = keys_at(&FINGERPRINT_16, AccountRole::Scan, ROTATION + 1);
        assert_ne!(first.account_hash(), next.account_hash());

        let mut keys = keys_at(&FINGERPRINT_16, AccountRole::Advertise, 0);
        assert!(keys.refresh());
        assert_eq!(keys.rotation_bucket, rotation_bucket_at(unix_time_ms(), 0));
        assert!(!keys.refresh());
    }

    #[test]
    fn obfuscation_matches_reference_and_round_trips() {
        let keys = keys_at(&FINGERPRINT_16, AccountRole::Advertise, ROTATION);
        let original = hex::decode("021861a1112233445566778899aabbccddee").unwrap();
        let mut packet = original.clone();
        let header = packet[4..9].to_vec();

        keys.obfuscate(&mut packet, &header);
        assert_eq!(hex(&packet), "021861a1112233445505fabaa7c2aa642703");

        keys.deobfuscate(&mut packet, &header);
        assert_eq!(packet, original);
    }

    #[test]
    fn extended_packet_uses_eight_byte_header() {
        let keys = keys_at(&FINGERPRINT_16, AccountRole::Advertise, ROTATION);
        let mut packet = vec![0x02, 0x18, 0x61, 0x21];
        packet.extend((4..21).map(|idx| idx as u8 * 0x0A));
        let header = packet[5..13].to_vec();

        keys.obfuscate(&mut packet, &header);
        assert_eq!(hex(&packet), "0218612128323c46505a646e78828c96085059d473");
    }

    #[test]
    fn secondary_packet_starts_xor_at_thirteen() {
        let keys = keys_at(&FINGERPRINT_16, AccountRole::Advertise, ROTATION);
        let mut packet = vec![0x02, 0x18, 0x61, 0x61];
        packet.extend((4..21).map(|idx| idx as u8 * 0x0A + 1));
        let header = packet[5..13].to_vec();

        keys.obfuscate(&mut packet, &header);
        assert_eq!(hex(&packet), "0218616129333d47515b656f79bde586095158d572");
    }

    #[test]
    fn short_packet_is_left_unchanged() {
        let keys = keys_at(&FINGERPRINT_16, AccountRole::Advertise, ROTATION);
        let original = vec![
            0x02, 0x18, 0x61, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        ];
        let mut packet = original.clone();
        let header = packet[4..9].to_vec();

        keys.obfuscate(&mut packet, &header);
        assert_eq!(packet, original);
    }

    #[test]
    fn advertising_mask_flips_only_set_bits() {
        let keys = keys_at(&FINGERPRINT_16, AccountRole::Advertise, ROTATION);
        let base = keys.build_mask();
        let filter = keys.build_filter();
        let mut flipped = [0u8; ACCOUNT_HASH_LEN];
        for idx in 0..ACCOUNT_HASH_LEN {
            flipped[idx] = keys.account_hash()[idx] ^ filter[idx];
            assert_eq!(flipped[idx] & base[idx], base[idx]);
        }
        assert_ne!(flipped, base);

        let repeat = keys_at(&FINGERPRINT_16, AccountRole::Advertise, ROTATION);
        assert_eq!(keys.account_hash(), repeat.account_hash());
    }

    #[test]
    fn empty_fingerprint_is_unconfigured() {
        let keys = BleKeyDerivation::new(Vec::new());
        assert!(!keys.is_configured());
        assert_eq!(keys.account_hash(), &[0u8; ACCOUNT_HASH_LEN]);
        assert_eq!(keys.ex_hash(), &[0u8; EX_HASH_LEN]);
        assert_eq!(keys.fingerprint_checksum(), 0);

        let original = hex::decode("021861a1112233445566778899aabbccddee").unwrap();
        let mut packet = original.clone();
        let header = packet[4..9].to_vec();
        keys.obfuscate(&mut packet, &header);
        assert_eq!(packet, original);
    }
}
