//! Shared protocol types for Samsung Continuity Service (mcfds)
//! Wire-level description of the Samsung Continuity protocol

#![allow(dead_code)] // Protocol helpers used by the RFCOMM and SPP paths.
pub mod command;

/// Samsung Bluetooth Company ID
pub const SAMSUNG_COMPANY_ID: u16 = 0x0075; // 117

/// CONTINUITY_MSG_SPP UUID
pub const CONTINUITY_MSG_SPP_UUID: &str = "3A622E58-C035-4A26-928C-5601DDE7C657";

/// Galaxy Buds Core SPP UUID (modern header)
pub const BUDS_SPP_NEW_UUID: &str = "2e73a4ad-332d-41fc-90e2-16bef06523f2";

/// Galaxy Buds SMEP SPP UUID
pub const BUDS_SMEP_SPP_UUID: &str = "f8620674-a1ed-41ab-a8b9-de9ad655729d";

// --- BLE Manufacturer Specific Data Layout ---

/// BLE advertisement header (first 3 bytes of manufacturer data)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BleHeader {
    pub version: u8, // Byte 0: always 0x02 for Samsung MCF
    pub subtype: u8, // Byte 1: always 0x18
    pub flags: u8,   // Byte 2: bit 7 = extended adv, bit 6 = secondary, lower 4 = sub-type
}

/// Offset of the format byte in the daemon's primary reading.
pub const FORMAT_BYTE_OFFSET_PRIMARY: usize = 3;
/// Offset of the format byte in the alternate (original-findings) reading.
pub const FORMAT_BYTE_OFFSET_ALTERNATE: usize = 2;

/// Low-nibble format flags: `0x00` long format, `0x01` short address format.
const FORMAT_NIBBLE_MASK: u8 = 0x0F;
const FORMAT_LONG: u8 = 0x00;
const FORMAT_SHORT: u8 = 0x01;

/// Returns the offset carrying a Samsung format byte, primary reading first.
///
/// [FR-008] Advertisements are reported with the format byte at offset 3 or,
/// in the original findings, at offset 2. The primary reading wins; callers
/// reject only when neither byte validates.
pub fn resolve_format_offset(data: &[u8]) -> Option<usize> {
    [FORMAT_BYTE_OFFSET_PRIMARY, FORMAT_BYTE_OFFSET_ALTERNATE]
        .into_iter()
        .find(|&offset| {
            data.get(offset)
                .is_some_and(|byte| matches!(byte & FORMAT_NIBBLE_MASK, FORMAT_LONG | FORMAT_SHORT))
        })
}

impl BleHeader {
    pub const EXPECTED_VERSION: u8 = 0x02;
    pub const EXPECTED_SUBTYPE: u8 = 0x18;

    pub const FLAG_EXTENDED_ADV: u8 = 0x80;
    pub const FLAG_SECONDARY: u8 = 0x40;
    pub const MASK_SUBTYPE: u8 = 0x0F;

    pub fn is_extended(&self) -> bool {
        self.flags & Self::FLAG_EXTENDED_ADV != 0
    }

    pub fn has_secondary(&self) -> bool {
        self.flags & Self::FLAG_SECONDARY != 0
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 3 {
            return None;
        }
        Some(Self {
            version: data[0],
            subtype: data[1],
            flags: data[2],
        })
    }

    pub fn to_bytes(self) -> [u8; 3] {
        [self.version, self.subtype, self.flags]
    }
}

/// Device context parsed from the BLE advertisement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceContext {
    /// Device context ID (short, big-endian in packet)
    pub coc: u16,
    /// Device State byte
    pub device_state: u8,
    /// Notification/Status flags byte
    pub notification_state: u8,
    /// Feature/capability flags byte
    pub features: u8,
    /// Audio playback info (short), present only when NS bit 2 is set
    pub audio_playback: Option<u16>,
}

impl DeviceContext {
    /// NS flag: feature indicator (bit 1)
    pub fn ns_flag_i(&self) -> bool {
        self.notification_state & 0x02 != 0
    }

    /// NS flag: audio playback present (bit 2)
    pub fn ns_flag_has_ap(&self) -> bool {
        self.notification_state & 0x04 != 0
    }

    /// NS flag: SCPM remote-revision support (bit 4)
    pub fn ns_flag_scpm(&self) -> bool {
        self.notification_state & 0x10 != 0
    }

    /// NS flag: secondary (bit 5)
    pub fn ns_flag_secondary(&self) -> bool {
        self.notification_state & 0x20 != 0
    }

    /// Audio state for Buds devices (from byte 9 of manufacturer data)
    pub fn buds_audio_state(&self) -> AudioState {
        match self.notification_state & 0xF8 {
            0x08 => AudioState::Idle,
            0x48 => AudioState::Streaming,
            _ => AudioState::Disconnected,
        }
    }
}

/// Audio state decoded from BLE manufacturer data byte 9
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioState {
    /// Idle or ambient (NS & 0xF8 == 0x08)
    Idle,
    /// Active audio streaming (NS & 0xF8 == 0x48)
    Streaming,
    /// Disconnected or in case
    Disconnected,
}

/// Valid device type values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Phone,
    Tablet,
    Watch,
    Buds,
    Speaker,
    Unknown(u8),
}

impl From<u8> for DeviceType {
    fn from(val: u8) -> Self {
        match val {
            1 => DeviceType::Phone,
            2 => DeviceType::Tablet,
            3 => DeviceType::Watch,
            4 => DeviceType::Buds,
            8 => DeviceType::Speaker,
            other => DeviceType::Unknown(other),
        }
    }
}

// --- Buds SPP Protocol ---

/// SPP message framing for Buds Core (modern 2-byte header)
pub mod buds_spp {
    /// Start of message byte (modern header)
    pub const SOM: u8 = 0xFD;
    /// End of message byte (modern header)
    pub const EOM: u8 = 0xDD;

    /// SPP message type bit (set in header for frames from earbuds)
    pub const TYPE_BIT: u16 = 0x1000;
    /// Fragment bit
    pub const FRAGMENT_BIT: u16 = 0x2000;
    /// Size mask (lower 10 bits)
    pub const SIZE_MASK: u16 = 0x03FF;

    /// Message IDs relevant to Auto Switch
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MsgId {
        ExtendedStatusUpdated, // 0x61 = 97
        SetSeamlessConnection, // 0xAF = 175
        AutoSwitchAudioOutput, // 0x73 = 115
        MultipointInfo,        // 0x76 = 118
        Acknowledgement,       // 0x42 = 66
        StatusUpdated,         // 0x60 = 96
    }

    impl MsgId {
        pub fn to_u8(self) -> u8 {
            match self {
                Self::ExtendedStatusUpdated => 0x61,
                Self::SetSeamlessConnection => 0xAF,
                Self::AutoSwitchAudioOutput => 0x73,
                Self::MultipointInfo => 0x76,
                Self::Acknowledgement => 0x42,
                Self::StatusUpdated => 0x60,
            }
        }

        pub fn from_u8(val: u8) -> Option<Self> {
            match val {
                0x61 => Some(Self::ExtendedStatusUpdated),
                0xAF => Some(Self::SetSeamlessConnection),
                0x73 => Some(Self::AutoSwitchAudioOutput),
                0x76 => Some(Self::MultipointInfo),
                0x42 => Some(Self::Acknowledgement),
                0x60 => Some(Self::StatusUpdated),
                _ => None,
            }
        }
    }

    impl std::convert::From<MsgId> for u8 {
        fn from(msg: MsgId) -> u8 {
            msg.to_u8()
        }
    }

    /// Encode a SPP frame for Buds Core
    pub fn encode_frame(msg_id: u8, payload: &[u8], is_response: bool) -> Vec<u8> {
        let size = (1 + payload.len() + 2) as u16; // msg_id + payload + crc16
        let mut header = size & SIZE_MASK;
        if is_response {
            header |= TYPE_BIT;
        }

        let mut frame = Vec::with_capacity(1 + 2 + 1 + payload.len() + 2 + 1);
        frame.push(SOM);
        frame.push((header & 0xFF) as u8);
        frame.push(((header >> 8) & 0xFF) as u8);
        frame.push(msg_id);
        frame.extend_from_slice(payload);

        // CRC16-CCITT over msg_id + payload
        let crc = crc16_ccitt(&frame[3..]);
        frame.push((crc & 0xFF) as u8);
        frame.push(((crc >> 8) & 0xFF) as u8);
        frame.push(EOM);

        frame
    }

    /// CRC16-CCITT (init=0, poly=0x1021, no final XOR, little-endian output)
    pub fn crc16_ccitt(data: &[u8]) -> u16 {
        let mut crc: u16 = 0;
        for &byte in data {
            crc ^= (byte as u16) << 8;
            for _ in 0..8 {
                if crc & 0x8000 != 0 {
                    crc = (crc << 1) ^ 0x1021;
                } else {
                    crc <<= 1;
                }
            }
        }
        crc
    }
}

// --- CONTINUITY_MSG_SPP Command Envelope ---

/// AutoSwitch command envelope (m3.a.K format)
#[derive(Debug, Clone)]
pub struct AutoSwitchCommand {
    pub device_addr: String,
    pub app_id: u8,
    pub app_seq: u8,
    pub command_type: u8,
    pub payload: Option<Vec<u8>>,
    pub flags: u8,
}

impl AutoSwitchCommand {
    /// Create a makeAutoSwitchRequest command
    pub fn make_request(device_addr: &str, account_token: &[u8], request_type: u8) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(device_addr.as_bytes());
        payload.extend_from_slice(account_token);
        payload.push(request_type);

        Self {
            device_addr: device_addr.to_string(),
            app_id: 1,
            app_seq: 1,
            command_type: 1,
            payload: Some(payload),
            flags: 0,
        }
    }

    /// Create a makeReadyEvent command
    pub fn make_ready_event(device_addr: &str) -> Self {
        Self {
            device_addr: device_addr.to_string(),
            app_id: 1,
            app_seq: 10,
            command_type: 3,
            payload: None,
            flags: 0,
        }
    }
}

// --- Scan Filter Patterns ---

/// Samsung MCF scan filter pattern
pub const SAMSUNG_MCF_FILTER_DATA: [u8; 3] = [0x02, 0x18, 0x01];
pub const SAMSUNG_MCF_FILTER_MASK: [u8; 3] = [0xFF, 0xFF, 0x0F];

/// Advertising data constants for Buds device matching
pub const BUDS_BASE_PATTERN: [u8; 10] =
    [0x42, 0x09, 0x81, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08];
pub const BUDS_NON_MATCH_MASK: [u8; 10] =
    [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78];
pub const BUDS_MATCH_MASK: [u8; 10] = [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38];
