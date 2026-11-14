//! BLE L2CAP Connection-Oriented Channel (CoC) client.
//!
//! Samsung MCF uses an LE CoC as the authenticated control channel. The PSM
//! comes from the type 1 LTV record in the peer's BLE advertisement.

use anyhow::{Context, Result, anyhow};
use bluer::l2cap::{
    FlowControl, PSM_LE_DYN_START, PSM_LE_MAX, Security, SecurityLevel, Socket, SocketAddr, Stream,
};
use bluer::{Address, AddressType};
use std::time::Duration;
use tokio::time::timeout;
use tracing::info;

/// Upper bound on a CoC connect attempt.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// An open BLE L2CAP Connection-Oriented Channel to a peer.
#[allow(dead_code)] // Read and written by the authentication handler in the next step.
#[derive(Debug)]
pub struct L2capChannel {
    /// Bidirectional byte stream (`AsyncRead + AsyncWrite`).
    pub stream: Stream,
    /// Protocol service multiplexor the peer advertised.
    pub psm: u16,
    /// Peer Bluetooth address.
    pub address: Address,
}

/// Connect to a BLE device over an L2CAP CoC on `psm`.
///
/// `address_type` must match the address the peer advertised with, otherwise
/// the kernel rejects the LE connection. The channel uses `SecurityLevel::High`,
/// which the phone accepted in captures; authentication still happens at the
/// application layer. After the connect, the phone sends nothing: it waits for
/// `AUTH_INITIATE` first (10 s watchdog), and frames messages as protobuf
/// varint-length delimited.
pub async fn connect_l2cap_coc(
    device_address: &str,
    address_type: AddressType,
    psm: u16,
) -> Result<L2capChannel> {
    if !(PSM_LE_DYN_START..=PSM_LE_MAX).contains(&psm) {
        return Err(anyhow!(
            "PSM {psm:#06x} is outside the LE CoC range \
             ({PSM_LE_DYN_START:#06x}..={PSM_LE_MAX:#06x})"
        ));
    }

    let address: Address = device_address
        .parse()
        .map_err(|_| anyhow!("invalid Bluetooth address {device_address:?}"))?;

    let socket = Socket::<Stream>::new_stream().context("create L2CAP stream socket")?;
    socket
        .bind(SocketAddr::any_le())
        .context("bind L2CAP socket")?;
    // LE CoC requires LE flow control; the kernel rejects the connect otherwise.
    socket
        .set_flow_control(FlowControl::Le)
        .context("set L2CAP LE flow control")?;
    socket
        .set_security(Security {
            level: SecurityLevel::High,
            key_size: 0,
        })
        .context("set L2CAP security level")?;

    info!(%address, ?address_type, psm, "Connecting BLE L2CAP CoC");
    let target = SocketAddr::new(address, address_type, psm);

    let stream = timeout(CONNECT_TIMEOUT, socket.connect(target))
        .await
        .map_err(|_| {
            anyhow!(
                "timed out after {:?} connecting to {address} PSM {psm:#06x}",
                CONNECT_TIMEOUT
            )
        })?
        .with_context(|| format!("connect to {address} PSM {psm:#06x}"))?;

    info!(%address, psm, "BLE L2CAP CoC connected");
    Ok(L2capChannel {
        stream,
        psm,
        address,
    })
}
