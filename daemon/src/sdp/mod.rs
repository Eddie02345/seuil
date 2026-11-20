//! SDP record registration for BlueZ

use anyhow::{Context, Result};
use std::io::Write;
use tracing::{debug, info, warn};

use crate::protocol::CONTINUITY_MSG_SPP_UUID;

/// Register the CONTINUITY_MSG_SPP SDP record with BlueZ
pub async fn register_sdp_record() -> Result<()> {
    info!(
        "Registering CONTINUITY_MSG_SPP SDP record: {}",
        CONTINUITY_MSG_SPP_UUID
    );

    // Build the SDP record XML
    let sdp_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<record>
    <attribute id="0x0001">
        <sequence>
            <uuid value="{}"/>
        </sequence>
    </attribute>
    <attribute id="0x0004">
        <sequence>
            <sequence>
                <uuid value="0x0100"/>
            </sequence>
            <sequence>
                <uuid value="0x0003"/>
                <uint8 value="0x00"/>
            </sequence>
        </sequence>
    </attribute>
    <attribute id="0x0005">
        <sequence>
            <uuid value="0x1002"/>
        </sequence>
    </attribute>
    <attribute id="0x0009">
        <sequence>
            <sequence>
                <uuid value="{}"/>
                <uint16 value="0x0100"/>
            </sequence>
        </sequence>
    </attribute>
    <attribute id="0x0100">
        <text value="CONTINUITY_MSG_SPP"/>
    </attribute>
</record>"#,
        CONTINUITY_MSG_SPP_UUID, CONTINUITY_MSG_SPP_UUID
    );

    debug!("SDP record XML:\n{}", sdp_xml);

    // [FR-013] Write to a unique owner-only temp file instead of a fixed /tmp
    // path another process could pre-create or symlink. Nothing consumes the
    // file yet, so it is removed once the advisory command is logged.
    let tmp_path = std::env::temp_dir().join(format!(
        "seuil-sdp-{}-{}.xml",
        std::process::id(),
        hex::encode(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos() as u64)
            .unwrap_or_default()
            .to_le_bytes())
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp_path)
        .with_context(|| format!("create {}", tmp_path.display()))?;
    file.write_all(sdp_xml.as_bytes())
        .with_context(|| format!("write {}", tmp_path.display()))?;
    drop(file);

    info!("SDP record written to {}", tmp_path.display());
    info!(
        "Register with: sdptool add --channel=7 {}",
        CONTINUITY_MSG_SPP_UUID
    );
    let _ = std::fs::remove_file(&tmp_path);

    Ok(())
}

/// Query SDP records on a remote device
pub async fn query_remote_sdp(address: &str) -> Result<Vec<SdpRecord>> {
    info!("Querying SDP records on {}", address);

    let output = tokio::process::Command::new("sdptool")
        .args(["browse", address])
        .output()
        .await
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "`sdptool` is not installed; install bluez-deprecated-tools on Arch, \
                     bluez on Debian/Ubuntu, or bluez-deprecated on Fedora"
                )
            } else {
                anyhow::Error::new(error).context(format!("run sdptool browse {address}"))
            }
        })?;

    // [FR-013] Distinguish a failing sdptool invocation from a missing tool and
    // from an absent service record.
    if !output.status.success() {
        let status = output
            .status
            .code()
            .map_or_else(|| "terminated by signal".to_string(), |code| format!("exit code {code}"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(
            address,
            %status,
            stderr = %stderr.trim(),
            "sdptool browse failed; the local SDP query usually needs bluetoothd's \
             compatibility flag"
        );
        anyhow::bail!(
            "`sdptool browse {address}` failed with {status}; this is a failed SDP query, \
             not a missing service record"
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut records = Vec::new();

    // Parse sdptool output
    let mut current_record = SdpRecord::default();
    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("Service Name:") {
            current_record.name = line.trim_start_matches("Service Name:").trim().to_string();
        } else if line.starts_with("Service RecHandle:") {
            current_record.handle = line
                .trim_start_matches("Service RecHandle:")
                .trim()
                .to_string();
        } else if line.contains(CONTINUITY_MSG_SPP_UUID) {
            current_record.is_continuity = true;
        }
        if line.is_empty() && !current_record.name.is_empty() {
            records.push(std::mem::take(&mut current_record));
        }
    }
    if !current_record.name.is_empty() {
        records.push(current_record);
    }

    info!("Found {} SDP records on {}", records.len(), address);
    Ok(records)
}

#[derive(Debug, Default, Clone)]
pub struct SdpRecord {
    pub name: String,
    pub handle: String,
    pub is_continuity: bool,
}
