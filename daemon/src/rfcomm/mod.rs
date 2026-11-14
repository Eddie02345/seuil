//! RFCOMM/SPP server and client for CONTINUITY_MSG_SPP

#![allow(dead_code)] // RFCOMM helper scaffolding; the handoff path currently uses the CoC.
use anyhow::Result;
use bluer::{Adapter, Address, Uuid};
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::protocol::{AutoSwitchCommand, CONTINUITY_MSG_SPP_UUID};

/// Event from the RFCOMM channel
#[derive(Debug, Clone)]
pub enum RfcommEvent {
    /// Connection established with remote device
    Connected { address: String },
    /// Disconnected from remote device
    Disconnected { address: String },
    /// Received a command/data frame
    Received { address: String, data: Vec<u8> },
}

/// RFCOMM server that listens for incoming CONTINUITY_MSG_SPP connections
pub struct RfcommServer {
    adapter: std::sync::Arc<Adapter>,
    event_tx: mpsc::Sender<RfcommEvent>,
}

impl RfcommServer {
    pub fn new(adapter: std::sync::Arc<Adapter>, event_tx: mpsc::Sender<RfcommEvent>) -> Self {
        Self { adapter, event_tx }
    }

    /// Register the SDP record and start listening
    pub async fn start(&self) -> Result<()> {
        let _uuid = Uuid::parse_str(CONTINUITY_MSG_SPP_UUID)?;
        info!(
            "Registering CONTINUITY_MSG_SPP SDP record: {}",
            CONTINUITY_MSG_SPP_UUID
        );

        // BlueZ handles SDP registration via the profile API
        self.register_profile().await?;

        info!("RFCOMM server started, listening for CONTINUITY_MSG_SPP connections");
        Ok(())
    }

    async fn register_profile(&self) -> Result<()> {
        // Register with BlueZ ProfileManager1 via D-Bus
        let _connection = zbus::Connection::system().await?;

        // TODO: Implement full BlueZ profile registration
        info!("SDP profile registration via BlueZ ProfileManager1 (TODO: full implementation)");
        Ok(())
    }
}

/// Connect to the phone's CONTINUITY_MSG_SPP service
pub async fn connect_to_phone(adapter: &Adapter, phone_address: Address) -> Result<()> {
    let device = adapter.device(phone_address)?;
    let uuid = Uuid::parse_str(CONTINUITY_MSG_SPP_UUID)?;

    info!("Connecting to phone {} CONTINUITY_MSG_SPP", phone_address);

    device.connect_profile(&uuid).await?;

    info!("Connected to phone CONTINUITY_MSG_SPP");
    Ok(())
}

/// Send an AutoSwitch command over the RFCOMM channel
pub async fn send_autoswitch_command(
    socket: &mut (impl tokio::io::AsyncWriteExt + Unpin),
    command: &AutoSwitchCommand,
) -> Result<()> {

    // Serialize the command envelope: app id, sequence, type, flags.
    let mut frame = vec![
        command.app_id,
        command.app_seq,
        command.command_type,
        command.flags,
    ];

    // Payload length (2 bytes, big-endian)
    let payload = command.payload.as_deref().unwrap_or(&[]);
    let payload_len = payload.len() as u16;
    frame.push((payload_len >> 8) as u8);
    frame.push((payload_len & 0xFF) as u8);

    // Payload data
    frame.extend_from_slice(payload);

    // Frame length prefix (2 bytes, big-endian)
    let frame_len = frame.len() as u16;
    socket
        .write_all(&[(frame_len >> 8) as u8, (frame_len & 0xFF) as u8])
        .await?;
    socket.write_all(&frame).await?;

    debug!(
        "Sent AutoSwitch command: type={} seq={} payload_len={}",
        command.command_type,
        command.app_seq,
        payload.len()
    );

    Ok(())
}
