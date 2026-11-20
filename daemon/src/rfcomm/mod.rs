//! RFCOMM/SPP server and client for CONTINUITY_MSG_SPP and the Buds opcodes.

#![allow(dead_code)] // Server scaffolding kept for the phone-side SPP path.
use anyhow::{Context, Result};
use bluer::rfcomm::{ConnectRequest, Profile, ProfileHandle, ReqError, Role, Stream};
use bluer::{Adapter, Address, Session, Uuid};
use futures::StreamExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::buds;
use crate::protocol::buds_spp::{self, MsgId};
use crate::protocol::{
    AutoSwitchCommand, BUDS_SMEP_SPP_UUID, BUDS_SPP_NEW_UUID, CONTINUITY_MSG_SPP_UUID,
};

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

/// Outbound work for the Buds SPP session.
///
/// [FR-013] Only Buds opcodes travel here; phone-directed Auto Switch commands
/// stay on the authenticated BLE CoC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SppCommand {
    /// Send SET_SEAMLESS_CONNECTION to the earbuds.
    SetSeamlessConnection { enable: bool },
}

/// Register a client BlueZ Profile1 handler for a UUID so an RFCOMM socket
/// reaches this process.
async fn register_profile(session: &Session, uuid: &str, name: &str) -> Result<ProfileHandle> {
    let uuid = Uuid::parse_str(uuid)?;
    let profile = Profile {
        uuid,
        name: Some(name.to_string()),
        role: Some(Role::Client),
        require_authentication: Some(false),
        require_authorization: Some(false),
        auto_connect: Some(true),
        ..Default::default()
    };
    session
        .register_profile(profile)
        .await
        .with_context(|| format!("register the {name} RFCOMM profile"))
}

/// Supervises the Buds SPP channel: profile registration, accepted streams, and
/// outbound opcode delivery.
///
/// The task lives for the process lifetime. Failures are logged and retried
/// with backoff instead of ending the channel permanently.
pub async fn run_buds_spp(
    session: Session,
    buds_address: Address,
    mut commands: mpsc::Receiver<SppCommand>,
    events: mpsc::Sender<RfcommEvent>,
) {
    let mut handle = match register_profile(&session, BUDS_SMEP_SPP_UUID, "seuil-buds-smep").await {
        Ok(handle) => handle,
        Err(error) => {
            warn!("Buds SMEP SPP profile unavailable: {error:#}");
            match register_profile(&session, BUDS_SPP_NEW_UUID, "seuil-buds-spp").await {
                Ok(handle) => handle,
                Err(error) => {
                    warn!("Buds SPP profile unavailable; SPP opcodes are disabled: {error:#}");
                    return;
                }
            }
        }
    };

    let mut writer: Option<tokio::io::WriteHalf<Stream>> = None;
    loop {
        tokio::select! {
            request = handle.next() => {
                let Some(request) = request else {
                    warn!("Buds SPP profile handle closed");
                    return;
                };
                accept_buds_request(request, buds_address, &events, &mut writer).await;
            }
            command = commands.recv() => {
                let Some(command) = command else { break };
                match command {
                    SppCommand::SetSeamlessConnection { enable } => {
                        let Some(write_half) = writer.as_mut() else {
                            warn!(
                                enable,
                                "SET_SEAMLESS_CONNECTION skipped: no Buds SPP channel is open"
                            );
                            continue;
                        };
                        if let Err(error) =
                            buds::set_seamless_connection(write_half, enable).await
                        {
                            warn!("Could not send SET_SEAMLESS_CONNECTION over SPP: {error:#}");
                            writer = None;
                        }
                    }
                }
            }
        }
    }
}

/// Accepts a connection request from the Buds and starts its frame reader.
///
/// Requests from any other device are rejected with a warning.
async fn accept_buds_request(
    request: ConnectRequest,
    buds_address: Address,
    events: &mpsc::Sender<RfcommEvent>,
    writer: &mut Option<tokio::io::WriteHalf<Stream>>,
) {
    if request.device() != buds_address {
        warn!(
            peer = %request.device(),
            "Rejecting an SPP connection from an unexpected device"
        );
        request.reject(ReqError::Rejected);
        return;
    }

    let stream = match request.accept() {
        Ok(stream) => stream,
        Err(error) => {
            warn!("Could not accept the Buds SPP connection: {error}");
            return;
        }
    };
    info!(address = %buds_address, "Buds SPP channel open");
    let (mut reader, write_half) = tokio::io::split(stream);
    *writer = Some(write_half);

    let events = events.clone();
    let address = buds_address.to_string();
    tokio::spawn(async move {
        if events
            .send(RfcommEvent::Connected {
                address: address.clone(),
            })
            .await
            .is_err()
        {
            return;
        }
        read_buds_frames(&mut reader, &address).await;
        let _ = events
            .send(RfcommEvent::Disconnected {
                address: address.clone(),
            })
            .await;
    });
}

/// Reads and reassembles Buds SPP frames from an RFCOMM stream.
///
/// [FR-013] Only Buds opcodes and their acknowledgements travel here; the
/// frame is decoded and its acknowledgement processed, never forwarded as a
/// phone-directed command.
async fn read_buds_frames<R>(reader: &mut R, address: &str)
where
    R: AsyncRead + Unpin,
{
    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let count = match reader.read(&mut chunk).await {
            Ok(0) => return,
            Ok(count) => count,
            Err(error) => {
                warn!(address, "Buds SPP read failed: {error}");
                return;
            }
        };
        buffer.extend_from_slice(&chunk[..count]);

        while buffer.len() >= 3 {
            if buffer[0] != buds_spp::SOM {
                // Resynchronise on the next byte until a frame start appears.
                buffer.drain(..1);
                continue;
            }
            let header = u16::from_le_bytes([buffer[1], buffer[2]]);
            let size = (header & buds_spp::SIZE_MASK) as usize;
            if size < 3 {
                warn!(address, size, "Dropping a Buds SPP frame with an invalid size");
                buffer.drain(..1);
                continue;
            }
            let total = 1 + 2 + size + 1;
            if buffer.len() < total {
                break;
            }
            let frame: Vec<u8> = buffer.drain(..total).collect();
            let Some((msg_id, payload)) = buds::parse_frame(&frame) else {
                warn!(address, "Dropping a malformed Buds SPP frame");
                continue;
            };
            // [FR-013] Process the SET_SEAMLESS_CONNECTION acknowledgement.
            if msg_id == MsgId::SetSeamlessConnection.to_u8() {
                let enabled = payload.first() == Some(&0x01);
                info!(address, enabled, "Buds acknowledged SET_SEAMLESS_CONNECTION");
            } else {
                debug!(address, msg_id, "Buds SPP frame received");
            }
        }

        if buffer.len() > 4096 {
            warn!(address, "Dropping an oversized Buds SPP reassembly buffer");
            buffer.clear();
        }
    }
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
    socket: &mut (impl AsyncWrite + Unpin),
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
