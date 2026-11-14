//! Galaxy Buds SPP protocol handler
//! Handles SET_SEAMLESS_CONNECTION and other Buds control messages

#![allow(dead_code)] // Buds SPP helper scaffolding for the direct-pull path.
use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

use crate::protocol::buds_spp::{self, MsgId};

/// Buds SPP connection state
#[derive(Debug)]
pub struct BudsConnection {
    /// Whether seamless connection is enabled on the earbuds
    pub seamless_enabled: bool,
    /// Main connection side (L=1, R=0)
    pub main_connection: u8,
    /// Battery levels
    pub battery_l: u8,
    pub battery_r: u8,
    /// Whether earbuds are coupled (both in ears)
    pub is_coupled: bool,
}

impl Default for BudsConnection {
    fn default() -> Self {
        Self {
            seamless_enabled: false,
            main_connection: 1,
            battery_l: 0,
            battery_r: 0,
            is_coupled: false,
        }
    }
}

/// Send SET_SEAMLESS_CONNECTION to the earbuds
/// Note: the boolean is INVERTED - 0x00 means enable, 0x01 means disable
pub async fn set_seamless_connection(
    socket: &mut (impl AsyncWriteExt + Unpin),
    enable: bool,
) -> Result<()> {
    // Inverted: 0x00 = enable, 0x01 = disable
    let payload_byte = if enable { 0x00 } else { 0x01 };
    let frame = buds_spp::encode_frame(MsgId::SetSeamlessConnection as u8, &[payload_byte], false);

    socket.write_all(&frame).await?;
    info!("Sent SET_SEAMLESS_CONNECTION: enable={}", enable);
    debug!("Frame: {}", hex::encode(&frame));
    Ok(())
}

/// Parse an Extended Status Update message from the earbuds
pub fn parse_extended_status_update(payload: &[u8]) -> Option<BudsConnection> {
    if payload.len() < 20 {
        return None;
    }

    Some(BudsConnection {
        main_connection: payload[5], // 1=L, 0=R
        battery_l: payload[2],
        battery_r: payload[3],
        is_coupled: payload[4] != 0,
        // Seamless flag at offset 19, inverted: 0 = enabled
        seamless_enabled: payload[19] == 0,
    })
}

/// Parse a received SPP frame
pub fn parse_frame(data: &[u8]) -> Option<(u8, Vec<u8>)> {
    if data.len() < 5 {
        return None;
    }

    if data[0] != buds_spp::SOM {
        warn!("Invalid SOM: 0x{:02X}", data[0]);
        return None;
    }

    let header = u16::from_le_bytes([data[1], data[2]]);
    let size = (header & buds_spp::SIZE_MASK) as usize;
    let _is_from_earbuds = header & buds_spp::TYPE_BIT != 0;

    if data.len() < 1 + 2 + size + 1 {
        warn!("Frame too short for size {}", size);
        return None;
    }

    let msg_id = data[3];
    let payload_start = 4;
    let payload_end = 1 + 2 + size - 2; // Exclude CRC (last 2 bytes before EOM)
    let payload = data[payload_start..payload_end].to_vec();

    let eom = data[1 + 2 + size];
    if eom != buds_spp::EOM {
        warn!(
            "Invalid EOM: 0x{:02X} (expected 0x{:02X})",
            eom,
            buds_spp::EOM
        );
        return None;
    }

    // Verify CRC
    let crc_received = u16::from_le_bytes([data[payload_end], data[payload_end + 1]]);
    let crc_computed = buds_spp::crc16_ccitt(&data[3..payload_end]);
    if crc_received != crc_computed {
        warn!(
            "CRC mismatch: received=0x{:04X} computed=0x{:04X}",
            crc_received, crc_computed
        );
        return None;
    }

    Some((msg_id, payload))
}
