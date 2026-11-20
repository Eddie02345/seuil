//! Command channel over an authenticated BLE L2CAP CoC.
//!
//! The phone dispatches received commands by handler id to a behavior
//! The phone dispatches received commands by handler id; handler 1 is Auto
//! Switch, so every Auto Switch message uses handler 1:
//!
//! | Message | handler | command | type |
//! |---|---|---|---|
//! | BUDS_SWITCH request | 1 | 1 | 1 |
//! | BUDS_SWITCH response | 1 | 1 | 2 |
//! | Ready event | 1 | 10 | 3 |
//!
//! Request body: `[adv id:2 big-endian][peer address:6][reason:1]`, where
//! `adv id = (xor(address bytes) << 8) | address[5]` and
//! reason 1 means media playback, 2 means a phone call.
//! Response body: `[result:1][adv id:2][address:6]`.

use anyhow::{anyhow, Result};
use bluer::l2cap::Stream;
use prost::Message;
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::protocol::command::{
    decrypt, encode_varint, encrypt, parse_frame, read_frame, McfCommand, McfPacket,
};

/// Handler id for the phone's Auto Switch behavior.
pub const HANDLER_AUTO_SWITCH: u64 = 1;
/// Handler id for channel control and keepalives.
pub const HANDLER_CHANNEL_CONTROL: u64 = 100;
/// Channel keepalive command id.
pub const COMMAND_KEEP: u64 = 3;
/// Get-device-state request; used as the outbound
/// keepalive because it is a read-only query.
pub const COMMAND_GET_DEVICE_STATE: u64 = 5;
/// Interval for the outbound keepalive. The phone closes a BLE command channel
/// after a short idle window ("Connection timeout"); a received non-control
/// command resets its timer, so the get-device-state
/// query keeps the channel open without changing any state.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Timeout bounds for one command channel, from config.toml.
#[derive(Debug, Clone, Copy)]
pub struct ChannelTimeouts {
    /// Upper bound on a keepalive write.
    pub keepalive: Duration,
    /// Upper bound on a frame send, and the floor of the inbound read window.
    pub frame: Duration,
}

impl Default for ChannelTimeouts {
    fn default() -> Self {
        Self {
            keepalive: Duration::from_secs(10),
            frame: Duration::from_secs(10),
        }
    }
}
/// BUDS_SWITCH command id.
pub const COMMAND_BUDS_SWITCH: u64 = 1;
/// Keep-alive "ready" event command id.
pub const COMMAND_READY: u64 = 10;
/// Request type.
pub const TYPE_REQUEST: u64 = 1;
/// Response type.
pub const TYPE_RESPONSE: u64 = 2;
/// Ready/stub event type.
pub const TYPE_EVENT: u64 = 3;

/// Reason byte for a media playback handoff.
pub const REASON_MEDIA: u8 = 1;
/// Reason byte for a phone-call handoff.
pub const REASON_CALL: u8 = 2;

/// Outgoing work for the command channel task.
#[derive(Debug, Clone)]
pub enum CommandRequest {
    /// Send a BUDS_SWITCH request to the phone.
    BudsSwitch {
        adv_id: u16,
        address: [u8; 6],
        reason: u8,
    },
    /// Send a BUDS_SWITCH response for a request from the phone.
    SwitchResponse {
        result: u8,
        adv_id: u16,
        address: [u8; 6],
    },
}

/// Incoming Auto Switch traffic decoded by the command channel task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncomingCommand {
    /// The phone asks this PC to hand the Buds over or to take them.
    BudsSwitchRequest {
        adv_id: u16,
        address: [u8; 6],
        reason: u8,
    },
    /// The phone answered a request sent by this PC.
    BudsSwitchResponse {
        result: u8,
        adv_id: u16,
        address: [u8; 6],
    },
}

/// Computes the advertisement id the phone uses for a peer address
/// high byte is the XOR of the six address bytes, low
/// byte is the last address byte.
pub fn advertisement_id(address: [u8; 6]) -> u16 {
    let xor = address.iter().fold(0u8, |acc, byte| acc ^ byte);
    (u16::from(xor) << 8) | u16::from(address[5])
}

/// Parses a Bluetooth address string into six bytes in string order.
pub fn parse_address(address: &str) -> Result<[u8; 6]> {
    let digits: String = address
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if digits.len() != 12 {
        return Err(anyhow!("invalid Bluetooth address {address:?}"));
    }
    let mut bytes = [0u8; 6];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[index * 2..index * 2 + 2], 16)
            .map_err(|_| anyhow!("invalid Bluetooth address {address:?}"))?;
    }
    Ok(bytes)
}

/// Builds the BUDS_SWITCH request body.
pub fn switch_request_body(adv_id: u16, address: [u8; 6], reason: u8) -> Vec<u8> {
    let mut body = Vec::with_capacity(9);
    body.extend_from_slice(&adv_id.to_be_bytes());
    body.extend_from_slice(&address);
    body.push(reason);
    body
}

/// Builds the BUDS_SWITCH response body.
pub fn switch_response_body(result: u8, adv_id: u16, address: [u8; 6]) -> Vec<u8> {
    let mut body = Vec::with_capacity(9);
    body.push(result);
    body.extend_from_slice(&adv_id.to_be_bytes());
    body.extend_from_slice(&address);
    body
}

/// Decodes a received command into Auto Switch traffic, when it is one.
pub fn decode_incoming(command: &McfCommand) -> Option<IncomingCommand> {
    if command.command_id != COMMAND_BUDS_SWITCH {
        return None;
    }
    let body = &command.payload;
    match command.msg_type {
        TYPE_REQUEST if body.len() >= 9 => Some(IncomingCommand::BudsSwitchRequest {
            adv_id: u16::from_be_bytes([body[0], body[1]]),
            address: body[2..8].try_into().ok()?,
            reason: body[8],
        }),
        TYPE_RESPONSE if body.len() >= 9 => Some(IncomingCommand::BudsSwitchResponse {
            result: body[0],
            adv_id: u16::from_be_bytes([body[1], body[2]]),
            address: body[3..9].try_into().ok()?,
        }),
        _ => None,
    }
}

/// Bound on the wait for the next inbound frame, measured from the last one.
///
/// [FR-012] A peer that answers keepalives is live even when it has no Auto
/// Switch traffic to send, so the inbound deadline must outlast a full
/// keepalive cycle instead of restarting on every unrelated branch. One cycle
/// plus the larger configured timeout keeps a keepalive-only channel open at
/// the defaults (25 s) while still bounding a peer that stops answering or
/// stalls mid-frame.
fn inbound_frame_deadline(keepalive: Duration, frame: Duration) -> Duration {
    KEEPALIVE_INTERVAL + keepalive.max(frame)
}

/// Runs the command channel until the transport closes.
///
/// Sends the ready event immediately, then serves outgoing requests and
/// forwards decoded Auto Switch traffic to `incoming`. Returns when the phone
/// closes the channel or the transport fails.
pub async fn run_command_channel(
    stream: Stream,
    session_key: [u8; 32],
    peer: String,
    mut outgoing: mpsc::Receiver<CommandRequest>,
    incoming: mpsc::Sender<(String, IncomingCommand)>,
    timeouts: ChannelTimeouts,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut sequence = 0u64;

    send_ready(&mut writer, &session_key, &mut sequence).await?;
    info!("Auto Switch ready event sent; command channel active");

    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick completes immediately; skip it so the keepalive starts
    // one interval after the ready event.
    keepalive.tick().await;

    // [FR-012] The inbound deadline counts from the last received frame, not
    // from the last select iteration, so a keepalive write does not reset it.
    let inbound_deadline = inbound_frame_deadline(timeouts.keepalive, timeouts.frame);
    let mut last_inbound = tokio::time::Instant::now();

    loop {
        let next_inbound = last_inbound + inbound_deadline;
        tokio::select! {
            _ = keepalive.tick() => {
                // [FR-012] A peer that stops draining keepalive writes tears
                // the channel down instead of stalling the task forever.
                let sent = tokio::time::timeout(
                    timeouts.keepalive,
                    send_command(&mut writer, &session_key, &mut sequence, HANDLER_AUTO_SWITCH, COMMAND_GET_DEVICE_STATE, TYPE_REQUEST, Vec::new()),
                )
                .await;
                match sent {
                    Err(_) => {
                        warn!(
                            timeout = ?timeouts.keepalive,
                            "keepalive write timed out; tearing down the command channel"
                        );
                        break;
                    }
                    Ok(Err(error)) => {
                        warn!("keepalive send failed: {error:#}");
                        break;
                    }
                    Ok(Ok(())) => {}
                }
            }
            request = outgoing.recv() => {
                let Some(request) = request else { break };
                let send = match request {
                    CommandRequest::BudsSwitch { adv_id, address, reason } => {
                        let body = switch_request_body(adv_id, address, reason);
                        send_command(
                            &mut writer,
                            &session_key,
                            &mut sequence,
                            HANDLER_AUTO_SWITCH,
                            COMMAND_BUDS_SWITCH,
                            TYPE_REQUEST,
                            body,
                        )
                    }
                    CommandRequest::SwitchResponse { result, adv_id, address } => {
                        let body = switch_response_body(result, adv_id, address);
                        send_command(
                            &mut writer,
                            &session_key,
                            &mut sequence,
                            HANDLER_AUTO_SWITCH,
                            COMMAND_BUDS_SWITCH,
                            TYPE_RESPONSE,
                            body,
                        )
                    }
                };
                let result = tokio::time::timeout(timeouts.frame, send).await;
                match result {
                    Err(_) => {
                        warn!(
                            timeout = ?timeouts.frame,
                            "command send timed out; tearing down the command channel"
                        );
                        break;
                    }
                    Ok(Err(error)) => {
                        warn!("command send failed: {error:#}");
                        break;
                    }
                    Ok(Ok(())) => {}
                }
            }
            _ = tokio::time::sleep_until(next_inbound) => {
                // [FR-012] A peer that has not answered within a full keepalive
                // cycle plus the configured timeout is stalled; the caller
                // removes the channel map entry.
                warn!(
                    window = ?inbound_deadline,
                    "no inbound command within the idle window; tearing down the command channel"
                );
                break;
            }
            frame = read_frame(&mut reader) => {
                let frame = match frame {
                    Err(error) => {
                        debug!("command channel closed: {error:#}");
                        break;
                    }
                    Ok(frame) => {
                        last_inbound = tokio::time::Instant::now();
                        frame
                    }
                };
                let packet = match parse_frame(&frame) {
                    Ok(packet) => packet,
                    Err(error) => {
                        warn!("command frame rejected: {error:#}");
                        continue;
                    }
                };
                let plaintext = match decrypt(&session_key, &packet.payload) {
                    Ok(plaintext) => plaintext,
                    Err(error) => {
                        warn!("command decryption failed: {error:#}");
                        continue;
                    }
                };
                let command = match McfCommand::decode(plaintext.as_slice()) {
                    Ok(command) => command,
                    Err(error) => {
                        warn!("command protobuf rejected: {error}");
                        continue;
                    }
                };
                debug!(
                    handler = packet.handler,
                    command = command.command_id,
                    msg_type = command.msg_type,
                    "command received"
                );
                // Channel keepalive: answer a keep request with the same id and
                // type 2, mirroring the phone's protocol.
                if packet.handler == HANDLER_CHANNEL_CONTROL
                    && command.command_id == COMMAND_KEEP
                    && command.msg_type == TYPE_REQUEST
                {
                    if let Err(error) = send_command(
                        &mut writer,
                        &session_key,
                        &mut sequence,
                        HANDLER_CHANNEL_CONTROL,
                        COMMAND_KEEP,
                        TYPE_RESPONSE,
                        Vec::new(),
                    )
                    .await
                    {
                        warn!("keepalive reply failed: {error:#}");
                        break;
                    }
                    continue;
                }
                if let Some(incoming_command) = decode_incoming(&command)
                    && incoming
                        .send((peer.clone(), incoming_command))
                        .await
                        .is_err()
                    {
                        break;
                    }
            }
        }
    }

    Ok(())
}

async fn send_ready<W>(writer: &mut W, session_key: &[u8; 32], sequence: &mut u64) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    send_command(
        writer,
        session_key,
        sequence,
        HANDLER_AUTO_SWITCH,
        COMMAND_READY,
        TYPE_EVENT,
        Vec::new(),
    )
    .await
}

async fn send_command<W>(
    writer: &mut W,
    session_key: &[u8; 32],
    sequence: &mut u64,
    handler: u64,
    command_id: u64,
    msg_type: u64,
    body: Vec<u8>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    *sequence += 1;
    let command = McfCommand {
        command_id,
        msg_type,
        payload: body,
    };
    let encrypted = encrypt(session_key, &command.encode_to_vec())?;
    let packet = McfPacket {
        handler,
        sequence: *sequence,
        payload: encrypted,
        adv_payload: Vec::new(),
        revision: 0,
        auth_type: 0,
        iv: Vec::new(),
    };
    let mut frame = Vec::with_capacity(packet.encoded_len() + 2);
    encode_varint(packet.encoded_len() as u64, &mut frame);
    packet
        .encode(&mut frame)
        .map_err(|e| anyhow!("encode command packet: {e}"))?;
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUDS: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

    #[test]
    fn inbound_frame_deadline_outlasts_one_keepalive_cycle() {
        // Defaults: a keepalive-only channel is never torn down by the read
        // bound, because the phone's reply resets it every 15 s.
        let default = inbound_frame_deadline(Duration::from_secs(10), Duration::from_secs(10));
        assert_eq!(default, Duration::from_secs(25));
        assert!(default > KEEPALIVE_INTERVAL);
        // Each configured timeout sets the floor of the window.
        assert_eq!(
            inbound_frame_deadline(Duration::from_secs(20), Duration::from_secs(10)),
            Duration::from_secs(35)
        );
        assert_eq!(
            inbound_frame_deadline(Duration::from_secs(5), Duration::from_secs(30)),
            Duration::from_secs(45)
        );
    }

    #[test]
    fn advertisement_id_is_xor_high_byte_and_last_byte_low() {
        let expected = (((0x44 ^ 0x55 ^ 0x66) as u16) << 8) | 0x66;
        assert_eq!(advertisement_id(BUDS), expected);
    }

    #[test]
    fn request_body_is_big_endian_adv_id_address_reason() {
        let body = switch_request_body(0x1234, BUDS, REASON_MEDIA);
        assert_eq!(body.len(), 9);
        assert_eq!(&body[0..2], &[0x12, 0x34]);
        assert_eq!(&body[2..8], &BUDS);
        assert_eq!(body[8], REASON_MEDIA);
    }

    #[test]
    fn request_decodes_with_the_receiver_field_order() {
        let command = McfCommand {
            command_id: COMMAND_BUDS_SWITCH,
            msg_type: TYPE_REQUEST,
            payload: switch_request_body(0xABCD, BUDS, REASON_CALL),
        };
        assert_eq!(
            decode_incoming(&command),
            Some(IncomingCommand::BudsSwitchRequest {
                adv_id: 0xABCD,
                address: BUDS,
                reason: REASON_CALL,
            })
        );
    }

    #[test]
    fn response_decodes_result_adv_id_address() {
        let command = McfCommand {
            command_id: COMMAND_BUDS_SWITCH,
            msg_type: TYPE_RESPONSE,
            payload: switch_response_body(1, 0x00E5, BUDS),
        };
        assert_eq!(
            decode_incoming(&command),
            Some(IncomingCommand::BudsSwitchResponse {
                result: 1,
                adv_id: 0x00E5,
                address: BUDS,
            })
        );
    }

    #[test]
    fn ready_command_is_ignored_by_the_decoder() {
        let command = McfCommand {
            command_id: COMMAND_READY,
            msg_type: TYPE_EVENT,
            payload: Vec::new(),
        };
        assert_eq!(decode_incoming(&command), None);
    }

    #[test]
    fn short_bodies_are_rejected() {
        let command = McfCommand {
            command_id: COMMAND_BUDS_SWITCH,
            msg_type: TYPE_REQUEST,
            payload: vec![0; 8],
        };
        assert_eq!(decode_incoming(&command), None);
    }

    #[test]
    fn address_parsing_matches_string_order() {
        assert_eq!(parse_address("11:22:33:44:55:66").unwrap(), BUDS);
    }
}
