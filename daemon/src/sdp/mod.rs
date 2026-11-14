//! SDP record registration and remote service discovery.
//!
//! Remote discovery reads the BlueZ `Device1.UUIDs` property, which BlueZ fills
//! from its SDP cache. That needs no `sdptool` binary, so discovery works on
//! immutable systems such as SteamOS where `bluez-deprecated-tools` is not
//! installed. `sdptool browse` remains as a fallback for BlueZ setups that have
//! not cached the peer's UUIDs yet.

use anyhow::{Context, Result};
use bluer::{Address, Session};
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

/// Query SDP records on a remote device.
///
/// BlueZ is the primary source. `sdptool` is optional and only consulted when
/// BlueZ has no cached UUIDs, so a missing `sdptool` never fails discovery.
pub async fn query_remote_sdp(address: &str) -> Result<Vec<SdpRecord>> {
    info!("Querying SDP records on {}", address);

    match query_via_bluez(address).await {
        Ok(records) if !records.is_empty() => return Ok(records),
        Ok(_) => debug!(
            "BlueZ has no cached SDP UUIDs for {}; trying sdptool",
            address
        ),
        Err(error) => debug!("BlueZ SDP lookup for {} failed: {error:#}", address),
    }

    query_via_sdptool(address).await
}

/// Reads the peer's service UUIDs from BlueZ's Device1 property.
async fn query_via_bluez(address: &str) -> Result<Vec<SdpRecord>> {
    let target: Address = address
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid Bluetooth address {address:?}"))?;
    let session = Session::new().await.context("connect to BlueZ")?;

    for adapter_name in session.adapter_names().await? {
        let Ok(adapter) = session.adapter(&adapter_name) else {
            continue;
        };
        let Ok(addresses) = adapter.device_addresses().await else {
            continue;
        };
        if !addresses.contains(&target) {
            continue;
        }

        let device = adapter.device(target)?;
        let alias = device.alias().await.unwrap_or_default();
        let uuids = device.uuids().await?.unwrap_or_default();
        if uuids.is_empty() {
            debug!(
                adapter = %adapter_name,
                "BlueZ knows {} but has no SDP UUIDs cached",
                address
            );
            return Ok(Vec::new());
        }

        let mut records: Vec<SdpRecord> = uuids
            .into_iter()
            .map(|uuid| {
                let value = uuid.to_string();
                let is_continuity = value.eq_ignore_ascii_case(CONTINUITY_MSG_SPP_UUID);
                SdpRecord {
                    name: if alias.is_empty() {
                        value.clone()
                    } else {
                        format!("{alias} ({value})")
                    },
                    uuid: value,
                    is_continuity,
                    ..SdpRecord::default()
                }
            })
            .collect();
        records.sort_by(|left, right| left.uuid.cmp(&right.uuid));

        info!(
            adapter = %adapter_name,
            count = records.len(),
            continuity = records.iter().any(|record| record.is_continuity),
            "Read {} SDP service UUIDs from BlueZ",
            records.len()
        );
        return Ok(records);
    }

    debug!("{} is not known to any BlueZ adapter", address);
    Ok(Vec::new())
}

/// Fallback discovery through `sdptool browse`, when the tool is installed.
async fn query_via_sdptool(address: &str) -> Result<Vec<SdpRecord>> {
    let output = match tokio::process::Command::new("sdptool")
        .args(["browse", address])
        .output()
        .await
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            debug!(
                "sdptool is not installed; BlueZ SDP UUIDs are the only lookup source"
            );
            return Ok(Vec::new());
        }
        Err(error) => return Err(error).context("run sdptool browse"),
    };

    let records = parse_sdptool_browse(&String::from_utf8_lossy(&output.stdout));
    info!("Found {} SDP records on {} with sdptool", records.len(), address);
    Ok(records)
}

/// Parses `sdptool browse` output into records.
fn parse_sdptool_browse(stdout: &str) -> Vec<SdpRecord> {
    let mut records = Vec::new();
    let mut current_record = SdpRecord::default();
    let continuity_uuid = CONTINUITY_MSG_SPP_UUID.to_ascii_lowercase();

    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("Service Name:") {
            if !current_record.name.is_empty() {
                records.push(std::mem::take(&mut current_record));
            }
            current_record.name = line.trim_start_matches("Service Name:").trim().to_string();
        } else if line.starts_with("Service RecHandle:") {
            current_record.handle = line
                .trim_start_matches("Service RecHandle:")
                .trim()
                .to_string();
        } else if let Some(rest) = line.strip_prefix("UUID ") {
            let uuid = rest
                .split_once(':')
                .map(|(_, value)| value.trim())
                .unwrap_or(rest.trim());
            if current_record.uuid.is_empty() {
                current_record.uuid = uuid.to_string();
            }
        }
        if line.to_ascii_lowercase().contains(&continuity_uuid) {
            current_record.is_continuity = true;
        }
        if line.is_empty() && !current_record.name.is_empty() {
            records.push(std::mem::take(&mut current_record));
        }
    }
    if !current_record.name.is_empty() {
        records.push(current_record);
    }
    records
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SdpRecord {
    pub name: String,
    pub handle: String,
    pub uuid: String,
    pub is_continuity: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
Service Name: Audio Sink
Service RecHandle: 0x10000
Service Class ID List:
  \"Audio Sink\" (0x110b)
Protocol Descriptor List:
  \"L2CAP\" (0x0100)

Service Name: CONTINUITY_MSG_SPP
Service RecHandle: 0x10001
Service Class ID List:
  UUID 128: 3a622e58-c035-4a26-928c-5601dde7c657

Service Name: Handsfree
Service RecHandle: 0x10002
";

    #[test]
    fn parses_sdptool_records_and_marks_continuity() {
        let records = parse_sdptool_browse(SAMPLE);

        assert_eq!(records.len(), 3);
        assert_eq!(records[0].name, "Audio Sink");
        assert_eq!(records[1].name, "CONTINUITY_MSG_SPP");
        assert!(records[1].is_continuity);
        assert_eq!(records[1].handle, "0x10001");
        assert_eq!(records[2].name, "Handsfree");
        assert!(!records[2].is_continuity);
    }

    #[test]
    fn marks_continuity_from_any_uuid_line() {
        let output = "Service Name: Opaque\n  UUID 128: 3A622E58-C035-4A26-928C-5601DDE7C657\n";
        let records = parse_sdptool_browse(output);
        assert_eq!(records.len(), 1);
        assert!(records[0].is_continuity);
    }

    #[test]
    fn empty_output_yields_no_records() {
        assert!(parse_sdptool_browse("").is_empty());
    }
}
