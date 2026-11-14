//! Samsung Continuity 3-message account authentication handshake.
//!
//! After the phone opens the L2CAP CoC channel it authenticates this PC with
//! three `CommandPacket` messages. Each packet wraps a protobuf body encrypted
//! with AES-256-GCM under the enrolled account key:
//!
//! | Message | Direction | Body |
//! |---|---|---|
//! | 1 `AUTH_INITIATE` | PC to phone | command 1, local BT address, P-256 SPKI, revision |
//! | 2 `AUTH_INITIATE_REPLY` | phone to PC | command 2, peer address, peer SPKI, proof of our SPKI |
//! | 3 `AUTH_REPLY` | PC to phone | command 3, proof of the peer SPKI, revision |
//!
//! The proof is the first six bytes of SHA-256 over the SPKI DER. A successful
//! handshake yields the raw P-256 ECDH shared secret, which the SPP command
//! layer uses as its AES-256-CBC key ([`docs/PROTOCOL_SPEC.md`] section 5.2).
//!
//! [`docs/PROTOCOL_SPEC.md`]: ../../../docs/PROTOCOL_SPEC.md

use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use p256::ecdh::diffie_hellman;
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use p256::{PublicKey, SecretKey};
use prost::Message;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::debug;

use super::{AuthError, Result};
use crate::protocol::command::{MAX_VARINT_LEN, McfPacket, encode_varint, parse_frame, read_frame};

/// Envelope handler id used by the handshake delegate.
const HANDLER_ID_HANDSHAKE: u64 = 0;

/// CommandPacket auth type for the Samsung account key.
const AUTH_TYPE_ACCOUNT: u64 = 1;

/// GCM nonce length required by the handshake.
const NONCE_LEN: usize = 12;

/// Length of the truncated SHA-256 proof carried in fields 5.
const PROOF_LEN: usize = 6;

/// Body command values.
const COMMAND_INITIATE: u64 = 1;
const COMMAND_INITIATE_REPLY: u64 = 2;
const COMMAND_REPLY: u64 = 3;

/// Inner authentication body. Field 4 carries the P-256 public
/// key in SPKI DER despite its historical `nonce` name.
#[derive(Clone, PartialEq, Message)]
struct AuthBody {
    #[prost(uint64, tag = "1")]
    command: u64,
    #[prost(int32, tag = "2")]
    result: i32,
    #[prost(bytes = "vec", tag = "3")]
    address: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    hash: Vec<u8>,
    #[prost(bool, tag = "7")]
    support_tcp_keep: bool,
    #[prost(uint32, optional, tag = "8")]
    scpm_revision: Option<u32>,
}

/// One side of the account handshake, holding the ephemeral P-256 key pair.
pub struct AuthHandshake {
    account_key: [u8; 32],
    bt_address: [u8; 6],
    revision: u32,
    private_key: SecretKey,
    public_key_der: Vec<u8>,
}

impl AuthHandshake {
    /// Creates a handshake with a fresh P-256 key pair.
    pub fn new(account_key: [u8; 32], bt_address: [u8; 6], revision: u32) -> Result<Self> {
        let private_key = SecretKey::random(&mut OsRng);
        let public_key_der = private_key
            .public_key()
            .to_public_key_der()
            .map_err(|e| AuthError::Crypto(format!("could not encode the handshake key: {e}")))?
            .as_bytes()
            .to_vec();

        Ok(Self {
            account_key,
            bt_address,
            revision,
            private_key,
            public_key_der,
        })
    }

    /// Builds the framed `AUTH_INITIATE` message for the phone.
    pub fn initiate(&self) -> Result<Vec<u8>> {
        let body = AuthBody {
            command: COMMAND_INITIATE,
            result: 0,
            address: self.bt_address.to_vec(),
            nonce: self.public_key_der.clone(),
            hash: Vec::new(),
            support_tcp_keep: true,
            scpm_revision: Some(self.revision),
        };
        let frame = self.frame(&body)?;
        debug!(
            address = %hex::encode(self.bt_address),
            revision = self.revision,
            "Sending AUTH_INITIATE"
        );
        Ok(frame)
    }

    /// Validates `AUTH_INITIATE_REPLY` and returns the `AUTH_REPLY` frame with
    /// the derived session key.
    ///
    /// `msg2` must be one complete length-prefixed message as read from the
    /// transport.
    pub fn respond(&self, msg2: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        let packet = parse_frame(msg2)
            .map_err(|e| AuthError::Protocol(format!("handshake frame is invalid: {e}")))?;
        if packet.handler != HANDLER_ID_HANDSHAKE {
            return Err(AuthError::Protocol(format!(
                "handshake reply uses handler {} instead of {HANDLER_ID_HANDSHAKE}",
                packet.handler
            )));
        }
        if packet.auth_type != AUTH_TYPE_ACCOUNT {
            return Err(AuthError::Protocol(format!(
                "handshake reply uses auth type {} instead of {AUTH_TYPE_ACCOUNT}",
                packet.auth_type
            )));
        }

        let plaintext = self.decrypt_body(&packet.payload)?;
        let body = AuthBody::decode(plaintext.as_slice())
            .map_err(|e| AuthError::Protocol(format!("handshake reply is not protobuf: {e}")))?;

        if body.command != COMMAND_INITIATE_REPLY {
            return Err(AuthError::Protocol(format!(
                "expected handshake stage {COMMAND_INITIATE_REPLY}, got {}",
                body.command
            )));
        }
        if body.result == -1 {
            return Err(AuthError::Protocol(
                "phone rejected the handshake initiate message".into(),
            ));
        }
        if body.address.len() != self.bt_address.len() {
            return Err(AuthError::Protocol(format!(
                "handshake reply carries a {}-byte address, expected {}",
                body.address.len(),
                self.bt_address.len()
            )));
        }

        let our_proof = proof(&self.public_key_der);
        if body.hash.as_slice() != our_proof.as_slice() {
            return Err(AuthError::Protocol(
                "phone proof of our public key does not match".into(),
            ));
        }

        let peer_public_key =
            PublicKey::from_public_key_der(body.nonce.as_slice()).map_err(|e| {
                AuthError::Protocol(format!("phone handshake key is not a P-256 SPKI: {e}"))
            })?;

        let shared = diffie_hellman(
            self.private_key.to_nonzero_scalar(),
            peer_public_key.as_affine(),
        );
        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(shared.raw_secret_bytes().as_slice());

        let reply = AuthBody {
            command: COMMAND_REPLY,
            result: 0,
            address: Vec::new(),
            nonce: Vec::new(),
            hash: proof(&body.nonce).to_vec(),
            support_tcp_keep: false,
            scpm_revision: Some(self.revision),
        };
        let frame = self.frame(&reply)?;
        debug!(
            peer_address = %hex::encode(&body.address),
            "Sending AUTH_REPLY"
        );
        Ok((frame, session_key))
    }

    /// Runs the full handshake over a framed transport and returns the session
    /// key. The timeout covers the whole exchange, so a silent phone cannot
    /// stall the caller.
    pub async fn authenticate<S>(&self, stream: &mut S, timeout: Duration) -> Result<[u8; 32]>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        tokio::time::timeout(timeout, self.exchange(stream))
            .await
            .map_err(|_| {
                AuthError::Handshake(format!(
                    "phone did not complete the handshake within {timeout:?}"
                ))
            })?
    }

    async fn exchange<S>(&self, stream: &mut S) -> Result<[u8; 32]>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Give the connection time to stabilize
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        let initiate = self.initiate()?;
        debug!("Attempting to write {} bytes to stream", initiate.len());
        match stream.write_all(&initiate).await {
            Ok(_) => debug!("Write succeeded"),
            Err(e) => {
                debug!("Write failed: {:?}", e);
                return Err(AuthError::Handshake(format!("write failed: {}", e)));
            }
        }
        stream.flush().await?;
        debug!("AUTH_INITIATE sent, waiting for reply...");

        let reply = read_frame(stream)
            .await
            .map_err(|e| AuthError::Handshake(format!("read failed: {e}")))?;
        debug!("Received {} bytes from phone", reply.len());

        let (frame, session_key) = self.respond(&reply)?;
        stream.write_all(&frame).await?;
        stream.flush().await?;
        debug!("AUTH_REPLY sent");

        Ok(session_key)
    }

    /// Encrypts and frames an authentication body.
    fn frame(&self, body: &AuthBody) -> Result<Vec<u8>> {
        let encrypted = self.encrypt_body(&body.encode_to_vec())?;
        let packet = McfPacket {
            handler: HANDLER_ID_HANDSHAKE,
            // The authentication delegate sends every handshake message with
            // a zero sequence number.
            sequence: 0,
            payload: encrypted,
            adv_payload: Vec::new(),
            revision: 0,
            auth_type: AUTH_TYPE_ACCOUNT,
            // The protocol fixes the handshake nonce to twelve zero bytes.
            iv: vec![0u8; NONCE_LEN],
        };

        let mut frame = Vec::with_capacity(packet.encoded_len() + MAX_VARINT_LEN);
        encode_varint(packet.encoded_len() as u64, &mut frame);
        packet.encode(&mut frame).map_err(|e| {
            AuthError::Protocol(format!("could not encode the handshake packet: {e}"))
        })?;
        Ok(frame)
    }

    /// AES-256-GCM under the account key.
    ///
    /// The Samsung protocol fixes the GCM nonce to zeros. That is a nonce-reuse
    /// weakness in the protocol itself, required here for interoperability;
    /// this helper must not be reused for command traffic.
    fn encrypt_body(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.account_key)
            .map_err(|e| AuthError::Crypto(format!("invalid account key: {e}")))?;
        cipher
            .encrypt(Nonce::from_slice(&[0u8; NONCE_LEN]), plaintext)
            .map_err(|_| AuthError::Crypto("handshake message encryption failed".into()))
    }

    fn decrypt_body(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.account_key)
            .map_err(|e| AuthError::Crypto(format!("invalid account key: {e}")))?;
        cipher
            .decrypt(Nonce::from_slice(&[0u8; NONCE_LEN]), ciphertext)
            .map_err(|_| {
                AuthError::Crypto(
                    "handshake reply could not be decrypted (wrong account key or corrupt frame)"
                        .into(),
                )
            })
    }
}

/// SHA-256 truncated to the six-byte proof.
fn proof(public_key_der: &[u8]) -> [u8; PROOF_LEN] {
    let digest = Sha256::digest(public_key_der);
    let mut truncated = [0u8; PROOF_LEN];
    truncated.copy_from_slice(&digest[..PROOF_LEN]);
    truncated
}
