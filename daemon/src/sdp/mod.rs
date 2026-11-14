//! SDP record registration for BlueZ

use anyhow::Result;
use tracing::{debug, info};

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

    // Write the SDP record to a temporary file and register it
    let tmp_path = "/tmp/seuil-sdp.xml";
    tokio::fs::write(tmp_path, &sdp_xml).await?;

    // Use sdptool to register the record
    // TODO: This requires root and BlueZ to be running
    info!("SDP record written to {}", tmp_path);
    info!(
        "Register with: sdptool add --channel=7 {}",
        CONTINUITY_MSG_SPP_UUID
    );

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
