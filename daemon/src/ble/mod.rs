//! BLE advertising and scanning for Samsung MCF (Company ID 0x0075)

use anyhow::{Context, Result};
use bluer::{Adapter, AddressType};
use futures::StreamExt;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::auth::ble_keys::{AccountRole, BleKeyDerivation};
use crate::auth::{Credentials, normalize_bt_address};
use crate::protocol::{AudioState, BleHeader, DeviceContext, DeviceType, SAMSUNG_COMPANY_ID};

pub mod coc_session;
pub mod l2cap;

/// Default L2CAP PSM advertised as the device context ID (`Coc`).
pub const DEFAULT_COC: u16 = 128;

/// State flags for the type 3 AD record while the Buds are connected to this
/// PC. Bits: 0x04 A2DP, 0x08 foreground, 0x20 wearing,
/// 0x40 SPP.
pub const BUDS_AD_FLAGS_CONNECTED: u8 = 0x6C;

/// Type 3 AD record: the connected Buds' advertisement id plus state flags
/// Emitted only while this PC owns the Buds
/// so the phone can map PC to Buds and target a handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudsAdRecord {
    pub adv_id: u16,
    pub flags: u8,
}

/// Update delivered to the advertiser task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvUpdate {
    /// Local audio state changed.
    Audio(AudioState),
    /// The connected Buds changed: `Some` while this PC owns them.
    Buds(Option<BudsAdRecord>),
}

/// Offset where the LTV block starts in an account-bound advertisement.
const LTV_START: usize = 16;

/// LTV record type 1: device context carrying the CoC PSM.
const LTV_TYPE_COC: u8 = 1;

/// OS nibble for One UI 6.1 and newer in the advertisement flags byte.
pub const ADV_FLAGS_OS_ONE_UI_61: u8 = 0x60;

/// Device kind for a phone in the advertisement flags byte.
pub const DEVICE_KIND_PHONE: u8 = 0x01;

/// LTV type 1 (device context) header for a 10-byte payload without audio.
pub const LTV_CTX_NO_AUDIO: u8 = 0xA1;

/// LTV type 1 (device context) header for an 11-byte payload with audio.
pub const LTV_CTX_WITH_AUDIO: u8 = 0xB1;

/// LTV type 4 (account sequence) header for a 3-byte payload.
pub const LTV_ACCOUNT_SEQUENCE: u8 = 0x34;

/// NS bit 2: audio playback field present.
const NS_AUDIO_PLAYBACK: u8 = 0x04;

/// NS bits for the idle audio state.
const NS_AUDIO_IDLE: u8 = 0x08;

/// NS bits for the streaming audio state.
const NS_AUDIO_STREAMING: u8 = 0x48;

/// Fields parsed from a Samsung MCF manufacturer data payload.
#[derive(Debug, Clone, Copy)]
pub struct ParsedMcfAdv {
    pub header: BleHeader,
    pub device_type: DeviceType,
    pub context: Option<DeviceContext>,
    pub audio_state: AudioState,
    /// L2CAP CoC PSM read from the type 1 LTV record.
    pub coc_psm: Option<u16>,
}

/// Event emitted when a Samsung MCF BLE advertisement is received
#[allow(dead_code)] // Diagnostic fields kept for logging and future filters.
#[derive(Debug, Clone)]
pub struct BleAdvEvent {
    pub address: String,
    pub address_type: AddressType,
    pub rssi: i16,
    pub header: BleHeader,
    pub device_type: DeviceType,
    pub context: Option<DeviceContext>,
    pub audio_state: AudioState,
    /// L2CAP CoC PSM advertised by the peer, when the type 1 record is present.
    pub coc_psm: Option<u16>,
    pub raw_data: Vec<u8>,
}

/// Parse manufacturer specific data from a BLE advertisement.
///
/// `keys` deobfuscates the LTV block so the type 1 CoC PSM can be read.
pub fn parse_mcf_manufacturer_data(data: &[u8], keys: &BleKeyDerivation) -> Option<ParsedMcfAdv> {
    let header = BleHeader::parse(data)?;
    debug!(
        "Parsed header: version={:02x} subtype={:02x} flags={:02x}",
        header.version, header.subtype, header.flags
    );

    if header.version != BleHeader::EXPECTED_VERSION
        || header.subtype != BleHeader::EXPECTED_SUBTYPE
    {
        return None;
    }

    if data.len() < 4 {
        debug!("Data too short: {} bytes", data.len());
        return None;
    }

    let device_type = DeviceType::from((data[3] & 0xF0) >> 4);

    let context = if data.len() >= 14 {
        let coc = u16::from_be_bytes([data[4], data[5]]);
        let device_state = data[6];
        let notification_state = data[7];
        let features = data[8];

        let audio_playback = if notification_state & 0x04 != 0 && data.len() >= 11 {
            Some(u16::from_be_bytes([data[9], data[10]]))
        } else {
            None
        };

        Some(DeviceContext {
            coc,
            device_state,
            notification_state,
            features,
            audio_playback,
        })
    } else {
        None
    };

    // Audio state from byte 9 (NS byte)
    let audio_state = if data.len() > 9 {
        match data[9] & 0xF8 {
            0x08 => AudioState::Idle,
            0x48 => AudioState::Streaming,
            _ => AudioState::Disconnected,
        }
    } else {
        AudioState::Disconnected
    };

    Some(ParsedMcfAdv {
        header,
        device_type,
        context,
        audio_state,
        coc_psm: parse_coc_psm(data, keys),
    })
}

/// Read the CoC PSM from the type 1 LTV record of an account-bound payload.
///
/// The LTV block is XOR-obfuscated with the account's SHA-256 table, so the
/// payload is deobfuscated on a copy before the records are walked.
fn parse_coc_psm(data: &[u8], keys: &BleKeyDerivation) -> Option<u16> {
    debug!(
        "parse_coc_psm: keys.is_configured()={}, data.len()={}, LTV_START={}",
        keys.is_configured(),
        data.len(),
        LTV_START
    );
    if !keys.is_configured() || data.len() <= LTV_START {
        debug!("parse_coc_psm: early return - keys not configured or data too short");
        return None;
    }

    let mut clear = data.to_vec();
    debug!(
        "parse_coc_psm: before deobfuscate, data[16..20]={:02x?}",
        &clear[16..20.min(clear.len())]
    );
    keys.deobfuscate(&mut clear, &[]);
    debug!(
        "parse_coc_psm: after deobfuscate, data[16..20]={:02x?}",
        &clear[16..20.min(clear.len())]
    );

    let mut index = LTV_START;
    while index < clear.len() {
        let header = clear[index];
        let length = (header >> 4) as usize;
        let kind = header & 0x0F;
        let body_start = index + 1;
        let body_end = body_start + length;

        // A zero length or a record that overruns the buffer ends parsing.
        if length == 0 || body_end > clear.len() {
            return None;
        }

        if kind == LTV_TYPE_COC {
            // Type 1 carries the CoC PSM as a big-endian short.
            if length < 2 {
                return None;
            }
            return Some(u16::from_be_bytes([
                clear[body_start],
                clear[body_start + 1],
            ]));
        }

        index = body_end;
    }

    None
}

/// Derive the scan-side keys used to deobfuscate phone advertisements.
///
/// An empty fingerprint yields an unconfigured instance, which leaves payloads
/// obfuscated and reports no CoC PSM.
pub fn scanning_keys(fingerprint: Option<&[u8]>) -> BleKeyDerivation {
    BleKeyDerivation::with_role(fingerprint.unwrap_or_default().to_vec(), AccountRole::Scan)
}

/// Start BLE scanning for Samsung MCF advertisements
pub async fn start_ble_scan(
    adapter: Arc<Adapter>,
    tx: mpsc::Sender<BleAdvEvent>,
    keys: BleKeyDerivation,
) -> Result<()> {
    info!(
        "Starting BLE scan for Samsung MCF (Company ID 0x{:04X})",
        SAMSUNG_COMPANY_ID
    );

    let mut stream = adapter.discover_devices_with_changes().await?;

    tokio::spawn(async move {
        while let Some(event) = stream.next().await {
            let bluer::AdapterEvent::DeviceAdded(addr) = event else {
                continue;
            };
            let Ok(device) = adapter.device(addr) else {
                continue;
            };
            debug!("Reading manufacturer data for device {}", addr);
            let Ok(Some(mfg_data)) = device.manufacturer_data().await else {
                continue;
            };
            debug!(
                "Got {} manufacturer data entries for {}",
                mfg_data.len(),
                addr
            );
            let Some(samsung_data) = mfg_data.get(&SAMSUNG_COMPANY_ID) else {
                continue;
            };
            debug!(
                "Samsung data from {} ({} bytes): {}",
                addr,
                samsung_data.len(),
                hex::encode(samsung_data)
            );
            let Some(parsed) = parse_mcf_manufacturer_data(samsung_data, &keys) else {
                debug_log_adv(&addr.to_string(), samsung_data);
                continue;
            };

            let address_type = device.address_type().await.unwrap_or(AddressType::LePublic);
            let rssi = device.rssi().await.unwrap_or(Some(-100)).unwrap_or(-100);
            let adv_event = BleAdvEvent {
                address: addr.to_string(),
                address_type,
                rssi,
                header: parsed.header,
                device_type: parsed.device_type,
                context: parsed.context,
                audio_state: parsed.audio_state,
                coc_psm: parsed.coc_psm,
                raw_data: samsung_data.clone(),
            };

            debug!(
                "MCF adv from {} type={:?} audio={:?} psm={:?} rssi={}",
                adv_event.address,
                adv_event.device_type,
                adv_event.audio_state,
                adv_event.coc_psm,
                adv_event.rssi
            );

            if tx.send(adv_event).await.is_err() {
                warn!("BLE scan event receiver dropped, stopping scan loop");
                break;
            }
        }
    });

    Ok(())
}

/// Reads the phone's current CoC PSM from its BlueZ advertisement data.
///
/// BlueZ keeps the latest manufacturer data per device, so this returns the
/// PSM from the most recent `0x0075` advertisement even when no fresh
/// `DeviceAdded` event arrives. Use it before dialing L2CAP after a failed
/// attempt instead of reusing a cached PSM.
pub async fn read_phone_coc_psm(
    adapter: &Adapter,
    address: &bluer::Address,
    keys: &BleKeyDerivation,
) -> Option<u16> {
    let device = adapter.device(*address).ok()?;
    let manufacturer_data = device.manufacturer_data().await.ok()??;
    let samsung_data = manufacturer_data.get(&SAMSUNG_COMPANY_ID)?;
    parse_mcf_manufacturer_data(samsung_data, keys).and_then(|parsed| parsed.coc_psm)
}

/// Advertise raw manufacturer data as a Samsung MCF packet.
#[allow(dead_code)] // Raw-payload entry point; main advertises through `advertiser_task`.
pub async fn start_ble_advertise(adapter: Arc<Adapter>, manufacturer_data: Vec<u8>) -> Result<()> {
    info!("Starting BLE advertisement with Samsung MCF data");

    let handle = register_advertisement(adapter, manufacturer_data).await?;
    hold_advertisement(handle);

    Ok(())
}

/// Build an account-bound advertisement and start advertising it.
#[allow(dead_code)] // Main uses `advertiser_task`, which re-advertises on audio changes.
pub async fn start_ble_advertise_with_account(
    adapter: Arc<Adapter>,
    key_derivation: &BleKeyDerivation,
    audio_state: AudioState,
    bt_address: [u8; 6],
) -> Result<()> {
    let handle = advertise_account(adapter, key_derivation, audio_state, bt_address, None).await?;
    hold_advertisement(handle);

    Ok(())
}

/// Keep an account-bound MCF advertisement in sync with the local audio state.
///
/// `bluer` cannot update a registered advertisement in place, so a state change
/// unregisters the current packet and registers a new one. A 12-hour timer
/// refreshes the rotating account keys and re-registers the advertisement so
/// the checksum never goes stale.
pub async fn advertiser_task(
    adapter: Arc<Adapter>,
    mut key_derivation: BleKeyDerivation,
    mut update_rx: mpsc::Receiver<AdvUpdate>,
) -> Result<()> {
    let bt_address = load_bt_address()?;
    let mut audio_state = AudioState::Idle;
    let mut buds: Option<BudsAdRecord> = None;
    let mut handle = advertise_account(
        adapter.clone(),
        &key_derivation,
        audio_state,
        bt_address,
        buds,
    )
    .await?;
    info!(?audio_state, "BLE advertisement started");

    let rotation_period = Duration::from_secs(43_200);
    let mut rotation_timer = tokio::time::interval_at(
        tokio::time::Instant::now() + rotation_period,
        rotation_period,
    );

    loop {
        tokio::select! {
            _ = rotation_timer.tick() => {
                let rotated = key_derivation.refresh();

                // Drop the old registration before advertising the replacement.
                drop(handle);
                handle = advertise_account(
                    adapter.clone(),
                    &key_derivation,
                    audio_state,
                    bt_address,
                    buds,
                )
                .await?;
                info!(rotated, "BLE advertisement rotation refreshed");
            }
            next_update = update_rx.recv() => {
                let Some(next_update) = next_update else {
                    break;
                };
                let rotated = key_derivation.refresh();
                let changed = match next_update {
                    AdvUpdate::Audio(next_state) => {
                        let changed = next_state != audio_state || rotated;
                        audio_state = next_state;
                        changed
                    }
                    AdvUpdate::Buds(next_buds) => {
                        let changed = next_buds != buds || rotated;
                        buds = next_buds;
                        changed
                    }
                };
                if !changed {
                    continue;
                }

                // Drop the old registration before advertising the replacement.
                drop(handle);
                handle = advertise_account(
                    adapter.clone(),
                    &key_derivation,
                    audio_state,
                    bt_address,
                    buds,
                )
                .await?;
                info!(?audio_state, ?buds, rotated, "BLE advertisement updated");
            }
        }
    }

    Ok(())
}

/// Load the local Bluetooth address used by the type 4 LTV hint.
fn load_bt_address() -> Result<[u8; 6]> {
    let credentials = Credentials::load()?
        .context("no stored Samsung credentials; cannot load the Bluetooth address hint")?;
    parse_bt_address(&credentials.bt_address)
}

/// Parse a normalized `AA:BB:CC:DD:EE:FF` address into six bytes.
fn parse_bt_address(address: &str) -> Result<[u8; 6]> {
    let normalized = normalize_bt_address(address)?;
    let mut bytes = [0u8; 6];
    for (index, part) in normalized.split(':').enumerate() {
        bytes[index] = u8::from_str_radix(part, 16)
            .with_context(|| format!("invalid Bluetooth address byte {part:?}"))?;
    }
    Ok(bytes)
}

/// Register the advertisement and keep its handle alive for the process.
///
/// Dropping `AdvertisementHandle` unregisters the advertisement, so the handle
/// is moved into a task that never completes.
#[allow(dead_code)] // Shared by the two public start functions above.
fn hold_advertisement(handle: bluer::adv::AdvertisementHandle) {
    tokio::spawn(async move {
        let _handle = handle;
        std::future::pending::<()>().await;
    });
}

/// Register a manufacturer data payload with the local adapter.
async fn register_advertisement(
    adapter: Arc<Adapter>,
    manufacturer_data: Vec<u8>,
) -> Result<bluer::adv::AdvertisementHandle> {
    let mut mfg_map = BTreeMap::new();
    mfg_map.insert(SAMSUNG_COMPANY_ID, manufacturer_data);

    let le_adv = bluer::adv::Advertisement {
        advertisement_type: bluer::adv::Type::Peripheral,
        manufacturer_data: mfg_map,
        ..Default::default()
    };

    adapter
        .advertise(le_adv)
        .await
        .context("failed to register MCF advertisement")
}

/// Build and register one account-bound advertisement.
async fn advertise_account(
    adapter: Arc<Adapter>,
    key_derivation: &BleKeyDerivation,
    audio_state: AudioState,
    bt_address: [u8; 6],
    buds: Option<BudsAdRecord>,
) -> Result<bluer::adv::AdvertisementHandle> {
    let manufacturer_data = build_mcf_advertisement_with_account(
        DEVICE_KIND_PHONE,
        audio_state,
        key_derivation,
        bt_address,
        DEFAULT_COC,
        buds,
    );

    // Never log the payload: it carries the account identity.
    info!(
        bytes = manufacturer_data.len(),
        ?audio_state,
        "Registering Samsung MCF advertisement"
    );

    register_advertisement(adapter, manufacturer_data).await
}

/// Advertisement flags byte: OS nibble in the upper half, device kind below.
pub fn advertisement_flags(device_type: u8) -> u8 {
    ADV_FLAGS_OS_ONE_UI_61 | (device_type & 0x0F)
}

/// Build an MCF advertising payload without account obfuscation.
///
/// Callers that hold a derived account should use
/// [`build_mcf_advertisement_with_account`], which adds the rotating account
/// hash and XOR obfuscation. `account_data` supplies the first five bytes of
/// the account hash; shorter input is zero-padded.
#[allow(dead_code)] // Clear-payload entry point for callers without derived keys.
pub fn build_mcf_advertisement(
    device_type: u8,
    audio_state: AudioState,
    account_data: &[u8],
) -> Vec<u8> {
    let mut account_hash = [0u8; 5];
    let len = account_data.len().min(account_hash.len());
    account_hash[..len].copy_from_slice(&account_data[..len]);

    build_clear_advertisement(
        device_type,
        audio_state,
        &account_hash,
        DEFAULT_COC,
        0x00,
        0x00,
        0x00,
    )
}

/// Build an MCF advertisement bound to a derived Samsung account.
///
/// Layout (`BluetoothChannel.swift:22-45`):
///
/// ```text
/// 0     0x02                    version
/// 1     0x18                    subtype
/// 2     checksum                XOR of ten rotated SHA-256 table bytes
/// 3     0x00 | 0x01             variant
/// 4     0x61 | 0x65             flags (phone | authenticated)
/// 5..13 8-byte extended hash    XOR seed
/// 13    0x21                    LTV version, low nibble is 1
/// 14    0x10                    LTV start offset, 16
/// 15    LTV length
/// 16..  LTV entries             XOR-obfuscated from offset 16
/// ```
///
/// The LTV block carries a type 1 extended device-context record
/// (`0x51`/`0x61`: CoC PSM, DS, NS, F, optional AP; the phone's parser needs at
/// least 5 payload bytes, the same shape the phone writes) and a type 3 local Bluetooth address hint
/// (the connected Buds' advertisement id and state flags).
pub fn build_mcf_advertisement_with_account(
    device_type: u8,
    audio_state: AudioState,
    key_derivation: &BleKeyDerivation,
    bt_address: [u8; 6],
    coc: u16,
    buds: Option<BudsAdRecord>,
) -> Vec<u8> {
    // Extended device context: PSM (big-endian), device state, notification
    // state, features. The audio-playback (AP) byte is absent, so the header
    // nibble is 5 (no AP would make it 6 with a `0x61` header).
    let notification_state = match audio_state {
        AudioState::Idle => NS_AUDIO_IDLE,
        AudioState::Streaming => NS_AUDIO_STREAMING,
        AudioState::Disconnected => 0x00,
    };
    let mut ltv = vec![
        (5 << 4) | LTV_TYPE_COC,
        (coc >> 8) as u8,
        (coc & 0xFF) as u8,
        0x00, // device state
        notification_state,
        0x00, // features
    ];
    // Type 3: AD record for the Buds this PC owns (2-byte advId big-endian,
    // then the state flags byte). Omitted while the Buds belong elsewhere.
    if let Some(buds) = buds {
        ltv.push((3 << 4) | 3);
        ltv.extend_from_slice(&buds.adv_id.to_be_bytes());
        ltv.push(buds.flags);
    }

    let mut data = Vec::with_capacity(16 + ltv.len());
    data.push(0x02);
    data.push(0x18);
    data.push(key_derivation.fingerprint_checksum());
    data.push(0x00);
    data.push(advertisement_flags(device_type));
    data.extend_from_slice(key_derivation.ex_hash());
    data.push(0x21);
    data.push(16);
    data.push(ltv.len() as u8);
    data.extend_from_slice(&ltv);

    // The XOR seed is the folded extended hash; obfuscate the LTV block only.
    let seed = data[5..13].iter().fold(0u8, |acc, &byte| acc ^ byte);
    let table = key_derivation.sha256_table();
    for index in 16..data.len() {
        data[index] ^= table[(seed as usize).wrapping_add(index) % table.len()];
    }

    // Debug: log the exact advertisement bytes
    tracing::info!("BLE advertisement: {} bytes", data.len());
    tracing::info!("  Hex: {}", hex::encode(&data));
    tracing::info!("  Checksum (byte 2): 0x{:02x}", data[2]);
    tracing::info!(
        "  BT address: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bt_address[0],
        bt_address[1],
        bt_address[2],
        bt_address[3],
        bt_address[4],
        bt_address[5]
    );
    if data.len() >= 22 {
        tracing::info!(
            "  Type 1 record (bytes 16..22): {}",
            hex::encode(&data[16..22])
        );
    }
    tracing::info!(
        "  Fingerprint checksum matches: {}",
        key_derivation.checksum_matches(data[2])
    );

    data
}

/// Build the plaintext advertisement before obfuscation.
fn build_clear_advertisement(
    device_type: u8,
    audio_state: AudioState,
    account_hash: &[u8; 5],
    coc: u16,
    device_state: u8,
    notification_state: u8,
    features: u8,
) -> Vec<u8> {
    let ns = match audio_state {
        AudioState::Idle => notification_state | NS_AUDIO_IDLE,
        AudioState::Streaming => notification_state | NS_AUDIO_STREAMING,
        AudioState::Disconnected => notification_state,
    };
    let has_audio_playback = ns & NS_AUDIO_PLAYBACK != 0;

    let mut data = Vec::with_capacity(if has_audio_playback { 19 } else { 18 });
    data.push(BleHeader::EXPECTED_VERSION);
    data.push(BleHeader::EXPECTED_SUBTYPE);
    data.push(advertisement_flags(device_type));
    data.push(if has_audio_playback {
        LTV_CTX_WITH_AUDIO
    } else {
        LTV_CTX_NO_AUDIO
    });
    data.extend_from_slice(account_hash);
    data.extend_from_slice(&coc.to_be_bytes());
    data.push(device_state);
    data.push(ns);
    data.push(features);
    if has_audio_playback {
        data.push(0x00); // AP placeholder, audio playback source unknown
    }

    // Type 4 account/sequence record: header, sequence, 2-byte value

    data.push(LTV_ACCOUNT_SEQUENCE);
    data.push(0x00); // sequence counter
    data.extend_from_slice(&coc.to_be_bytes());

    data
}

/// Build the scan response for an extended advertisement.
///
/// Layout:
///
/// ```text
/// 02 18 <fpChecksum> <01|41> <flags> <8-byte exHash>
/// [21 10 <extraLen>] <51|61> <Coc:2> <DS> <NS> <F> [AP]
/// ```
///
/// `extra_len` is the size of the extended context plus any extra LTV records.
/// A zero value selects the `0x41` secondary flag and omits the length header.
/// An `AP` value in `context` selects the `0x61` context header and appends the
/// playback byte.
///
/// BlueZ's D-Bus advertisement object has no scan-response field, so callers
/// that split an extended payload must publish it through their own transport.
#[allow(dead_code)] // BlueZ has no scan-response field; extended callers publish it.
pub fn build_mcf_scan_response(
    fingerprint_checksum: u8,
    flags: u8,
    ex_hash: &[u8; 8],
    extra_len: u8,
    context: &DeviceContext,
) -> Vec<u8> {
    let has_audio_playback = context.ns_flag_has_ap();
    let mut data = Vec::with_capacity(14 + extra_len as usize);
    data.push(BleHeader::EXPECTED_VERSION);
    data.push(BleHeader::EXPECTED_SUBTYPE);
    data.push(fingerprint_checksum);
    data.push(if extra_len == 0 { 0x41 } else { 0x01 });
    data.push(flags);
    data.extend_from_slice(ex_hash);
    if extra_len > 0 {
        data.push(0x21);
        data.push(0x10);
        data.push(extra_len);
    }

    data.push(if has_audio_playback { 0x61 } else { 0x51 });
    data.extend_from_slice(&context.coc.to_be_bytes());
    data.push(context.device_state);
    data.push(context.notification_state);
    data.push(context.features);
    if has_audio_playback {
        data.push(context.audio_playback.unwrap_or(0) as u8);
    }

    data
}

// Debug: log raw advertisement data
#[allow(dead_code)]
fn debug_log_adv(address: &str, data: &[u8]) {
    debug!(
        "Raw MCF adv from {} ({} bytes): {}",
        address,
        data.len(),
        hex::encode(data)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINGERPRINT: [u8; 16] = [0x11; 16];
    const COC: u16 = 0x0080;
    const BT_ADDRESS: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    fn keys() -> BleKeyDerivation {
        BleKeyDerivation::new(FINGERPRINT.to_vec())
    }

    fn deobfuscate_ltv(advertisement: &mut [u8], keys: &BleKeyDerivation) {
        let seed = advertisement[5..13]
            .iter()
            .fold(0u8, |acc, &byte| acc ^ byte);
        let table = keys.sha256_table();
        for index in 16..advertisement.len() {
            advertisement[index] ^= table[(seed as usize).wrapping_add(index) % table.len()];
        }
    }

    #[test]
    fn advertisement_header_matches_mcf_layout() {
        let keys = keys();
        let adv = build_mcf_advertisement_with_account(
            DEVICE_KIND_PHONE,
            AudioState::Idle,
            &keys,
            BT_ADDRESS,
            COC,
            None,
        );

        assert_eq!(&adv[0..2], &[0x02, 0x18]);
        assert_eq!(adv[2], keys.fingerprint_checksum());
        assert!(keys.checksum_matches(adv[2]));
        assert_eq!(adv[3], 0x00);
        assert_eq!(adv[4], 0x61);
        assert_eq!(advertisement_flags(DEVICE_KIND_PHONE), 0x61);
        assert_eq!(&adv[5..13], keys.ex_hash());
        assert_eq!(&adv[13..16], &[0x21, 16, 6]);
        assert_eq!(adv.len(), 16 + adv[15] as usize);
    }

    #[test]
    fn advertisement_obfuscates_ltv_block_from_sixteen() {
        let keys = keys();
        let mut adv = build_mcf_advertisement_with_account(
            DEVICE_KIND_PHONE,
            AudioState::Streaming,
            &keys,
            BT_ADDRESS,
            COC,
            Some(BudsAdRecord {
                adv_id: 0xF463,
                flags: BUDS_AD_FLAGS_CONNECTED,
            }),
        );

        // The extended type 1 CoC record is obfuscated, not clear.
        let clear_coc = [0x51, (COC >> 8) as u8, (COC & 0xFF) as u8];
        assert_ne!(&adv[16..19], &clear_coc);

        deobfuscate_ltv(&mut adv, &keys);
        assert_eq!(&adv[16..19], &clear_coc);
        assert_eq!(&adv[19..22], &[0x00, NS_AUDIO_STREAMING, 0x00]);
        assert_eq!(&adv[22..26], &[0x33, 0xF4, 0x63, BUDS_AD_FLAGS_CONNECTED]);
    }

    #[test]
    fn scan_keys_extract_coc_psm_from_type1_record() {
        let advertisement = build_mcf_advertisement_with_account(
            DEVICE_KIND_PHONE,
            AudioState::Idle,
            &keys(),
            BT_ADDRESS,
            COC,
            None,
        );
        let scan_keys = scanning_keys(Some(&FINGERPRINT));

        let parsed =
            parse_mcf_manufacturer_data(&advertisement, &scan_keys).expect("advertisement parses");

        assert_eq!(parsed.coc_psm, Some(COC));
    }

    #[test]
    fn scan_response_matches_extended_layout() {
        let ex_hash = [0xAB; 8];
        let context = DeviceContext {
            coc: COC,
            device_state: 0x00,
            notification_state: NS_AUDIO_PLAYBACK,
            features: 0x00,
            audio_playback: Some(0x00),
        };
        let scr = build_mcf_scan_response(0x5A, 0x61, &ex_hash, 12, &context);

        assert_eq!(&scr[0..2], &[0x02, 0x18]);
        assert_eq!(scr[2], 0x5A);
        assert_eq!(scr[3], 0x01);
        assert_eq!(scr[4], 0x61);
        assert_eq!(&scr[5..13], &ex_hash);
        assert_eq!(&scr[13..16], &[0x21, 0x10, 12]);
        assert_eq!(scr[16], 0x61);
        assert_eq!(&scr[17..19], &COC.to_be_bytes());
    }
}
