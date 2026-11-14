//! Continuity command channel: outer envelope, inner command, and AES-CBC framing.
//!
//! After the 3-message account handshake the same transport carries commands.
//! The envelope is `McfPacket`, the inner message is `McfCommand`
//! (`McfCommand`), and the payload is AES-256-CBC with PKCS#7 padding under the
//! ECDH session key, with a random 16-byte IV prepended.

use aes::Aes256;
use anyhow::{anyhow, Result};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use prost::Message;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Maximum accepted frame body. Command messages are a few hundred bytes.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

/// Longest valid protobuf varint, in bytes.
pub const MAX_VARINT_LEN: usize = 10;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// Outer envelope for every Continuity message.
#[derive(Clone, PartialEq, Message)]
pub struct McfPacket {
    #[prost(uint64, tag = "1")]
    pub handler: u64,
    #[prost(uint64, tag = "2")]
    pub sequence: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub payload: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub adv_payload: Vec<u8>,
    #[prost(uint64, tag = "5")]
    pub revision: u64,
    #[prost(uint64, tag = "6")]
    pub auth_type: u64,
    #[prost(bytes = "vec", tag = "7")]
    pub iv: Vec<u8>,
}

/// Inner command: command id, message type, payload.
#[derive(Clone, PartialEq, Message)]
pub struct McfCommand {
    #[prost(uint64, tag = "1")]
    pub command_id: u64,
    #[prost(uint64, tag = "2")]
    pub msg_type: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub payload: Vec<u8>,
}

/// Encrypts a command body with a random IV prepended.
pub fn encrypt(session_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut iv = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    let cipher = Aes256CbcEnc::new_from_slices(session_key, &iv)
        .map_err(|e| anyhow!("invalid session key: {e}"))?;
    let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext);
    let mut out = Vec::with_capacity(iv.len() + ciphertext.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts a command body with its prepended IV.
pub fn decrypt(session_key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 32 || !(data.len() - 16).is_multiple_of(16) {
        return Err(anyhow!("command ciphertext has an invalid length"));
    }
    let (iv, ciphertext) = data.split_at(16);
    let cipher = Aes256CbcDec::new_from_slices(session_key, iv)
        .map_err(|e| anyhow!("invalid session key: {e}"))?;
    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| anyhow!("command decryption failed: {e}"))
}

/// Appends a protobuf varint to `out`.
pub fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Decodes a protobuf varint, returning the value and the bytes consumed.
pub fn decode_varint(data: &[u8]) -> Result<(u64, usize)> {
    let mut value = 0u64;
    for (index, &byte) in data.iter().take(MAX_VARINT_LEN).enumerate() {
        if index == MAX_VARINT_LEN - 1 && byte > 1 {
            return Err(anyhow!("length prefix overflows a u64"));
        }
        value |= u64::from(byte & 0x7F) << (7 * index as u32);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    Err(anyhow!("frame has no complete length prefix"))
}

/// Splits a complete frame into its packet, rejecting truncated input.
pub fn parse_frame(frame: &[u8]) -> Result<McfPacket> {
    let (len, header_len) = decode_varint(frame)?;
    let len = usize::try_from(len).map_err(|_| anyhow!("frame length does not fit in memory"))?;
    if len > MAX_FRAME_LEN {
        return Err(anyhow!("frame length {len} exceeds the {MAX_FRAME_LEN}-byte limit"));
    }
    let payload = frame
        .get(header_len..header_len + len)
        .ok_or_else(|| anyhow!("frame is shorter than its length prefix"))?;
    if frame.len() != header_len + len {
        return Err(anyhow!("frame carries bytes past its declared length"));
    }
    McfPacket::decode(payload).map_err(|e| anyhow!("frame is not an MCF packet: {e}"))
}

/// Reads one length-prefixed packet from an async transport.
pub async fn read_frame<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut length = 0u64;
    let mut byte = [0u8; 1];
    let mut header_len = 0;
    let mut header = Vec::new();

    loop {
        stream.read_exact(&mut byte).await?;
        header.push(byte[0]);
        let bits = u64::from(byte[0] & 0x7F);
        length |= bits
            .checked_shl(7 * header_len as u32)
            .ok_or_else(|| anyhow!("length prefix overflows"))?;
        header_len += 1;
        if byte[0] & 0x80 == 0 {
            break;
        }
        if header_len >= MAX_VARINT_LEN {
            return Err(anyhow!("length prefix is too long"));
        }
    }

    let len = usize::try_from(length).map_err(|_| anyhow!("frame length does not fit in memory"))?;
    if len > MAX_FRAME_LEN {
        return Err(anyhow!("frame length {len} exceeds the {MAX_FRAME_LEN}-byte limit"));
    }

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    header.extend_from_slice(&payload);
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbc_round_trips_and_prepends_the_iv() {
        let key = [0x42u8; 32];
        let plaintext = b"buds switch request payload";
        let ciphertext = encrypt(&key, plaintext).expect("encrypt");
        assert_eq!((ciphertext.len() - 16) % 16, 0);
        assert_ne!(&ciphertext[16..], plaintext.as_slice());
        let decrypted = decrypt(&key, &ciphertext).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_rejects_short_and_misaligned_input() {
        let key = [0x00u8; 32];
        assert!(decrypt(&key, &[0u8; 16]).is_err());
        assert!(decrypt(&key, &[0u8; 40]).is_err());
    }

    #[test]
    fn command_encodes_as_protobuf_fields_one_two_three() {
        let command = McfCommand {
            command_id: 1,
            msg_type: 2,
            payload: vec![0xAA, 0xBB],
        };
        let encoded = command.encode_to_vec();
        let decoded = McfCommand::decode(encoded.as_slice()).expect("decode");
        assert_eq!(decoded, command);
    }

    #[test]
    fn packet_round_trips_through_a_frame() {
        let packet = McfPacket {
            handler: 1,
            sequence: 7,
            payload: vec![1, 2, 3],
            adv_payload: Vec::new(),
            revision: 68,
            auth_type: 0,
            iv: Vec::new(),
        };
        let mut frame = Vec::new();
        encode_varint(packet.encoded_len() as u64, &mut frame);
        packet.encode(&mut frame).expect("encode");
        let parsed = parse_frame(&frame).expect("parse");
        assert_eq!(parsed, packet);
    }
}
