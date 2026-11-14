#!/usr/bin/env python3
"""Probe the Samsung MCF transports used by Galaxy Buds Auto Switch.

The tool has three independent probes:

* BlueZ over D-Bus (``dbus-fast``) for the resolved service UUIDs of a device.
* ``sdptool browse`` for the raw SDP records and the RFCOMM channel assigned to
  ``CONTINUITY_MSG_SPP``. BlueZ 5 does not expose SDP attribute records or
  RFCOMM channels over D-Bus, so this probe supplies the channel number.
* A BLE scan (``bleak``) for manufacturer data under company ID 0x0075, decoded
  with the Samsung MCF frame layout.

Byte offsets in the decoder follow ``docs/PROTOCOL_SPEC.md`` section 2.2: the
manufacturer-specific value starts at the vendor version byte, so offset 0 is
the first byte after the 2-byte company ID.

Usage:
    python3 probe_sdp_and_ble.py [--mac XX:XX:XX:XX:XX:XX]
                                 [--ble-only | --sdp-only]
                                 [--duration 30] [--connect] [--no-sdptool]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

COMPANY_ID = 0x0075
CONTINUITY_UUID = "3a622e58-c035-4a26-928c-5601dde7c657"
UUID_BASE_SUFFIX = "-0000-1000-8000-00805f9b34fb"
BLUEZ_SERVICE = "org.bluez"
BLUEZ_ROOT = "/"
OBJECT_MANAGER = "org.freedesktop.DBus.ObjectManager"
DEVICE_IFACE = "org.bluez.Device1"
PROPERTIES_IFACE = "org.freedesktop.DBus.Properties"

SAMSUNG_NAME_RE = re.compile(r"samsung|galaxy|sm-|buds", re.IGNORECASE)
MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

LOG = logging.getLogger("probe")


class ProbeError(RuntimeError):
    """A probe could not run to completion."""


class JsonLogFormatter(logging.Formatter):
    """Emit one JSON object per log record."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(debug: bool, json_logs: bool) -> None:
    handler = logging.StreamHandler(sys.stderr)
    if json_logs:
        handler.setFormatter(JsonLogFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S")
        )
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.WARNING)
    LOG.setLevel(logging.DEBUG if debug else logging.INFO)


def install_excepthook() -> None:
    """Keep an unexpected failure from printing a bare traceback."""

    def hook(exc_type: type[BaseException], exc: BaseException, tb: Any) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc, tb)
            return
        LOG.critical("unhandled exception", exc_info=(exc_type, exc, tb))

    sys.excepthook = hook


# ---------------------------------------------------------------------------
# UUID and byte helpers
# ---------------------------------------------------------------------------


def normalize_uuid(value: str) -> str:
    """Return a lowercase 128-bit UUID for 16-bit, 32-bit, or 128-bit input."""
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if re.fullmatch(r"[0-9a-f]{4}", text):
        return f"0000{text}{UUID_BASE_SUFFIX}"
    if re.fullmatch(r"[0-9a-f]{8}", text):
        return f"{text}{UUID_BASE_SUFFIX}"
    return text



def hex_bytes(data: bytes) -> str:
    return " ".join(f"{byte:02x}" for byte in data)


def hex_preview(data: bytes, limit: int = 24) -> str:
    if len(data) <= limit:
        return hex_bytes(data)
    return f"{hex_bytes(data[:limit])} ... ({len(data)} bytes)"


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


# ---------------------------------------------------------------------------
# MCF advertisement decoder
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Tlv:
    type: int
    payload: bytes

    @property
    def name(self) -> str:
        return {
            1: "Ctx",
            2: "Event",
            3: "AD",
            4: "Account",
            5: "Unknown5",
            6: "ClientList",
            7: "RCSeq",
            8: "Uint32",
        }.get(self.type, f"Type{self.type}")


@dataclass(slots=True)
class McfFrame:
    raw: bytes
    version: int
    subtype: int
    flags: int
    device_type: int
    device_flags: int
    account: bytes
    tlvs: list[Tlv]
    issues: list[str] = field(default_factory=list)

    @property
    def extended(self) -> bool:
        return bool(self.flags & 0x80)

    @property
    def secondary(self) -> bool:
        return bool(self.flags & 0x40)

    @property
    def sub_type(self) -> int:
        return self.flags & 0x0F

    @property
    def ns(self) -> int | None:
        """Notification/status byte at absolute manufacturer-data offset 9."""
        return self.raw[9] if len(self.raw) > 9 else None

    @property
    def audio_state(self) -> tuple[int, str]:
        ns = self.ns
        if ns is None:
            return 2, "unknown (no NS byte)"
        high = ns & 0xF8
        if high == 0x08:
            return 0, "idle/ambient"
        if high == 0x48:
            return 1, "streaming"
        return 2, "disconnected/case"

    @property
    def wearing(self) -> bool | None:
        if len(self.raw) <= 36:
            return None
        return bool(self.raw[36] & 0x01)


def parse_account(account: bytes) -> str:
    """Decode the type-4 account LTV carried in offsets 4..12 when present."""
    if len(account) >= 2 and (account[0] & 0x0F) == 4:
        length = account[0] >> 4
        if 2 <= length <= len(account) - 1:
            payload = account[1 : 1 + length]
            sequence = payload[0]
            if len(payload) >= 3:
                account_id = int.from_bytes(payload[1:3], "big")
                return f"seq={sequence} account=0x{account_id:04x}"
            return f"seq={sequence} payload={payload.hex()}"
    return "raw=" + hex_preview(account, limit=9)


def describe_tlv(tlv: Tlv) -> str:
    payload = tlv.payload
    if tlv.type == 1 and len(payload) >= 11:
        coc = int.from_bytes(payload[5:7], "big")
        return (
            f"coc=0x{coc:04x} ds=0x{payload[7]:02x} ns=0x{payload[8]:02x} "
            f"f=0x{payload[9]:02x} ap=0x{payload[10]:02x}"
        )
    if tlv.type == 2 and len(payload) >= 2:
        return f"header=0x{payload[0]:02x} seq={payload[1]} data={hex_preview(payload[2:], 12)}"
    if tlv.type == 3 and len(payload) >= 3:
        adv = int.from_bytes(payload[0:2], "big")
        flags = payload[2]
        parts = [
            f"adv=0x{adv:04x}",
            f"hfp={flags & 0x03}",
            f"a2dp={'yes' if flags & 0x04 else 'no'}",
            f"fg={'yes' if flags & 0x08 else 'no'}",
            f"bis={'yes' if flags & 0x10 else 'no'}",
            f"wear={'yes' if flags & 0x20 else 'no'}",
            f"spp={'yes' if flags & 0x40 else 'no'}",
        ]
        if len(payload) >= 5:
            battery = (payload[3] & 0x0F) * 10 + ((payload[4] & 0xF0) >> 4)
            parts.append(f"battery={battery}%")
            if payload[3] & 0x80:
                parts.append("ws=1")
        return " ".join(parts)
    if tlv.type == 4 and len(payload) >= 2:
        return f"seq={payload[0]} payload={hex_preview(payload[1:], 8)}"
    if tlv.type == 8 and len(payload) == 4:
        return f"value={int.from_bytes(payload, 'big')}"
    return hex_preview(payload, limit=12)


def parse_mcf_frame(data: bytes) -> McfFrame:
    """Parse vendor data for company 0x0075. Raises ValueError when too short."""
    if len(data) < 4:
        raise ValueError(f"manufacturer data too short ({len(data)} bytes, need at least 4)")
    version = data[0]
    subtype = data[1]
    flags = data[2]
    device_type = (data[3] >> 4) & 0x0F
    device_flags = data[3] & 0x0F
    account = data[4:13]
    issues: list[str] = []
    if version != 0x02:
        issues.append(f"unexpected version 0x{version:02x} (expected 0x02)")
    if subtype != 0x18:
        issues.append(f"unexpected subtype 0x{subtype:02x} (expected 0x18)")
    if flags & 0x80 and len(data) < 21:
        issues.append("extended flag set but packet is shorter than 21 bytes")
    if flags & 0x40 and len(data) < 18:
        issues.append("secondary flag set but packet is shorter than 18 bytes")

    tlvs: list[Tlv] = []
    offset = 13
    while offset < len(data):
        header = data[offset]
        length = header >> 4
        record_type = header & 0x0F
        if length == 0:
            break
        end = offset + 1 + length
        if end > len(data):
            issues.append(f"truncated TLV type {record_type} at offset {offset}")
            tlvs.append(Tlv(record_type, data[offset + 1 :]))
            break
        tlvs.append(Tlv(record_type, data[offset + 1 : end]))
        offset = end

    return McfFrame(
        raw=data,
        version=version,
        subtype=subtype,
        flags=flags,
        device_type=device_type,
        device_flags=device_flags,
        account=account,
        tlvs=tlvs,
        issues=issues,
    )


def format_frame_detail(frame: McfFrame) -> list[str]:
    state_number, state_label = frame.audio_state
    wear = frame.wearing
    wear_label = "unknown" if wear is None else ("yes" if wear else "no")
    lines = [
        f"raw     : {hex_bytes(frame.raw)}",
        (
            f"header  : version=0x{frame.version:02x} subtype=0x{frame.subtype:02x} "
            f"extended={'yes' if frame.extended else 'no'} "
            f"secondary={'yes' if frame.secondary else 'no'} "
            f"sub-type={frame.sub_type}"
        ),
        f"device  : type=0x{frame.device_type:x} flags=0x{frame.device_flags:x}",
        f"account : {parse_account(frame.account)}",
        (
            f"audio   : {state_label} (state={state_number}, "
            f"NS=0x{frame.ns:02x}) wearing={wear_label}"
            if frame.ns is not None
            else f"audio   : {state_label} wearing={wear_label}"
        ),
    ]
    if frame.tlvs:
        for tlv in frame.tlvs:
            lines.append(f"tlv {tlv.type:<2}  : {tlv.name:<10} len={len(tlv.payload):<2} {describe_tlv(tlv)}")
    else:
        lines.append("tlv     : none")
    for issue in frame.issues:
        lines.append(f"issue   : {issue}")
    return lines


# ---------------------------------------------------------------------------
# BlueZ D-Bus probe
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class BluezDevice:
    path: str
    address: str
    name: str
    alias: str
    adapter: str
    paired: bool
    connected: bool
    services_resolved: bool
    uuids: list[str]
    manufacturer_data: dict[int, bytes]

    @property
    def label(self) -> str:
        return self.alias or self.name or "(unnamed)"


def _dbus_error_text(reply: Any) -> str:
    if reply.body:
        return str(reply.body[0])
    return "no error text"


async def dbus_call(
    bus: Any,
    destination: str,
    path: str,
    interface: str,
    member: str,
    signature: str = "",
    body: list[Any] | None = None,
    timeout: float = 10.0,
) -> Any:
    from dbus_fast import Message, MessageType

    message = Message(
        destination=destination,
        path=path,
        interface=interface,
        member=member,
        signature=signature,
        body=body or [],
    )
    try:
        reply = await asyncio.wait_for(bus.call(message), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise ProbeError(f"D-Bus call {interface}.{member} timed out after {timeout:.1f}s") from exc
    if reply.message_type == MessageType.ERROR:
        from dbus_fast import DBusError

        raise DBusError(reply.error_name, _dbus_error_text(reply))
    return reply


def _unwrap(value: Any) -> Any:
    from dbus_fast import Variant, unpack_variants

    if isinstance(value, Variant):
        return unpack_variants(value)
    if isinstance(value, dict):
        return {_unwrap(key): _unwrap(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_unwrap(item) for item in value]
    return value


def _device_from_props(path: str, props: dict[str, Any]) -> BluezDevice | None:
    address = _unwrap(props.get("Address"))
    if not isinstance(address, str):
        return None
    manufacturer: dict[int, bytes] = {}
    raw_manufacturer = _unwrap(props.get("ManufacturerData")) or {}
    if isinstance(raw_manufacturer, dict):
        for company, value in raw_manufacturer.items():
            if isinstance(company, int) and isinstance(value, (bytes, bytearray)):
                manufacturer[company] = bytes(value)
    uuids = _unwrap(props.get("UUIDs")) or []
    return BluezDevice(
        path=path,
        address=address.upper(),
        name=str(_unwrap(props.get("Name")) or ""),
        alias=str(_unwrap(props.get("Alias")) or ""),
        adapter=str(_unwrap(props.get("Adapter")) or ""),
        paired=bool(_unwrap(props.get("Paired"))),
        connected=bool(_unwrap(props.get("Connected"))),
        services_resolved=bool(_unwrap(props.get("ServicesResolved"))),
        uuids=[str(item) for item in uuids],
        manufacturer_data=manufacturer,
    )


async def fetch_bluez_devices(bus: Any, timeout: float) -> list[BluezDevice]:
    reply = await dbus_call(
        bus,
        BLUEZ_SERVICE,
        BLUEZ_ROOT,
        OBJECT_MANAGER,
        "GetManagedObjects",
        timeout=timeout,
    )
    objects = reply.body[0] if reply.body else {}
    devices: list[BluezDevice] = []
    for path, interfaces in objects.items():
        props = interfaces.get(DEVICE_IFACE)
        if not props:
            continue
        device = _device_from_props(path, props)
        if device:
            devices.append(device)
    return devices


def select_device(devices: list[BluezDevice], mac: str | None) -> BluezDevice | None:
    if mac:
        target = mac.upper()
        for device in devices:
            if device.address.upper() == target:
                return device
        return None
    if not devices:
        return None

    def score(device: BluezDevice) -> int:
        value = 0
        if CONTINUITY_UUID in {normalize_uuid(uuid) for uuid in device.uuids}:
            value += 100
        if SAMSUNG_NAME_RE.search(f"{device.alias} {device.name}"):
            value += 20
        if device.paired:
            value += 5
        if device.connected:
            value += 3
        if COMPANY_ID in device.manufacturer_data:
            value += 2
        return value

    best = max(devices, key=score)
    if score(best) <= 0:
        return None
    LOG.info("auto-selected %s (%s)", best.address, best.label)
    return best


async def connect_for_sdp(bus: Any, device: BluezDevice, timeout: float) -> None:
    from dbus_fast import DBusError

    LOG.info("requesting BlueZ connect to trigger SDP resolution on %s", device.address)
    try:
        await dbus_call(
            bus,
            BLUEZ_SERVICE,
            device.path,
            DEVICE_IFACE,
            "Connect",
            timeout=timeout,
        )
    except (DBusError, ProbeError) as exc:
        # AlreadyConnected and InProgress are benign here.
        LOG.debug("BlueZ Connect returned %s", exc)


async def probe_dbus_sdp(mac: str | None, args: argparse.Namespace) -> tuple[bool, BluezDevice | None]:
    try:
        from dbus_fast import BusType, DBusError
        from dbus_fast.aio import MessageBus
    except ImportError as exc:
        LOG.error("dbus-fast is not installed: %s", exc)
        return False, None

    print("\n== SDP via BlueZ D-Bus ==")

    try:
        bus = await asyncio.wait_for(
            MessageBus(bus_type=BusType.SYSTEM).connect(), timeout=args.timeout
        )
    except (OSError, asyncio.TimeoutError, DBusError) as exc:
        LOG.error("cannot connect to the system bus: %s", exc)
        return False, None

    try:
        devices = await fetch_bluez_devices(bus, args.timeout)
        device = select_device(devices, mac)
        if device is None:
            if mac:
                print(f"Device {mac}: not present in BlueZ managed objects")
            else:
                print("No Bluetooth device found. Pass --mac to name one.")
            if devices:
                print("BlueZ devices:")
                for item in devices:
                    print(f"  {item.address}  {item.label}  paired={item.paired} connected={item.connected}")
            return False, None

        if args.connect and not device.services_resolved:
            await connect_for_sdp(bus, device, args.timeout)
            devices = await fetch_bluez_devices(bus, args.timeout)
            refreshed = select_device(devices, device.address)
            if refreshed:
                device = refreshed

        spp_present = CONTINUITY_UUID in {normalize_uuid(uuid) for uuid in device.uuids}
        print(f"Device          : {device.address}  {device.label}")
        print(f"Adapter         : {device.adapter or 'unknown'}")
        print(f"Paired/connected: {'yes' if device.paired else 'no'} / "
              f"{'yes' if device.connected else 'no'}")
        print(f"ServicesResolved: {'yes' if device.services_resolved else 'no'}")
        spp_label = "present in BlueZ UUID cache" if spp_present else "not present in BlueZ UUID cache"
        print(f"SPP UUID        : {spp_label}")
        if device.uuids:
            print(f"UUIDs ({len(device.uuids)}):")
            for uuid in device.uuids:
                marker = "  <-- CONTINUITY_MSG_SPP" if normalize_uuid(uuid) == CONTINUITY_UUID else ""
                print(f"  {uuid}{marker}")
        else:
            print("UUIDs           : none resolved")
        company_data = device.manufacturer_data.get(COMPANY_ID)
        if company_data:
            print(f"Company 0x0075  : {hex_preview(company_data, 40)}")
        else:
            print("Company 0x0075  : no cached manufacturer data")
        print(
            "Note: BlueZ 5 exposes resolved UUIDs, not SDP attribute records or "
            "RFCOMM channel numbers. The sdptool probe below supplies the channel."
        )
        if not device.services_resolved and not args.connect:
            print("Hint: pass --connect to let BlueZ connect once and resolve services.")
        return True, device
    except (ProbeError, DBusError, OSError) as exc:
        LOG.error("BlueZ D-Bus query failed: %s", exc)
        return False, None
    finally:
        try:
            bus.disconnect()
        except Exception:  # A failed disconnect must not hide the probe result.
            LOG.debug("system bus disconnect failed", exc_info=True)


# ---------------------------------------------------------------------------
# sdptool probe
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SdpRecord:
    handle: str
    name: str
    uuids: list[str]
    rfcomm_channel: int | None
    psm: int | None


SDP_UUID_128_RE = re.compile(r"UUID\s+128:\s*([0-9a-fA-F-]{36})")
SDP_UUID_GENERIC_RE = re.compile(
    r"\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b"
)
SDP_UUID_16_RE = re.compile(r'"([^"]+)"\s+\((0x[0-9a-fA-F]{4})\)')


def parse_sdptool_output(text: str) -> list[SdpRecord]:
    """Parse ``sdptool browse`` output into one record per Service RecHandle.

    ``sdptool`` prints ``Service Name:`` on the line *before* ``Service
    RecHandle:``, so names are carried forward until the handle line opens a
    record.
    """
    records: list[SdpRecord] = []
    current: SdpRecord | None = None
    pending_name = ""

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        name_match = re.match(r"^Service Name:\s*(.+)$", line)
        if name_match:
            pending_name = name_match.group(1).strip()
            continue
        description_match = re.match(r"^Service Description:\s*(.+)$", line)
        if description_match and not pending_name:
            pending_name = description_match.group(1).strip()
            continue
        handle_match = re.match(r"^Service RecHandle:\s*(0x[0-9a-fA-F]+)\s*$", line)
        if handle_match:
            current = SdpRecord(
                handle=handle_match.group(1),
                name=pending_name,
                uuids=[],
                rfcomm_channel=None,
                psm=None,
            )
            records.append(current)
            pending_name = ""
            continue
        if current is None:
            continue

        for uuid_match in SDP_UUID_128_RE.finditer(line):
            value = normalize_uuid(uuid_match.group(1))
            if value not in current.uuids:
                current.uuids.append(value)
        for uuid_match in SDP_UUID_GENERIC_RE.finditer(line):
            value = normalize_uuid(uuid_match.group(1))
            if value not in current.uuids:
                current.uuids.append(value)
        for _, short_uuid in SDP_UUID_16_RE.findall(line):
            value = normalize_uuid(short_uuid)
            if value not in current.uuids:
                current.uuids.append(value)
        if current.rfcomm_channel is None:
            channel_match = re.match(r"^\s*Channel:\s*(\d+)\s*$", line)
            if channel_match:
                current.rfcomm_channel = int(channel_match.group(1))
        if current.psm is None:
            psm_match = re.match(r"^\s*PSM:\s*(\d+)\s*$", line)
            if psm_match:
                current.psm = int(psm_match.group(1))

    return records


def run_sdptool(mac: str, timeout: float) -> tuple[int, str, str, str]:
    executable = shutil.which("sdptool")
    if not executable:
        raise ProbeError("sdptool not found in PATH (install bluez-deprecated-tools on Arch/CachyOS, bluez on Debian/Ubuntu, or bluez-deprecated on Fedora)")
    try:
        completed = subprocess.run(
            [executable, "browse", mac],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProbeError(f"sdptool browse {mac} timed out after {timeout:.1f}s") from exc
    except OSError as exc:
        raise ProbeError(f"cannot run sdptool: {exc}") from exc
    return completed.returncode, completed.stdout, completed.stderr, executable


def probe_sdptool(device: BluezDevice | None, mac: str | None, args: argparse.Namespace) -> bool:
    print("\n== SDP records via sdptool ==")
    target = mac or (device.address if device else None)
    if not target:
        print("No MAC address available for sdptool browse.")
        return False
    if not MAC_RE.match(target):
        print(f"Invalid MAC address: {target}")
        return False
    if args.no_sdptool:
        print("Skipped (--no-sdptool).")
        return False

    try:
        returncode, stdout, stderr, executable = run_sdptool(target.upper(), args.timeout)
    except ProbeError as exc:
        LOG.error("%s", exc)
        return False

    if returncode != 0:
        first_error = (stderr or stdout).strip().splitlines()
        detail = first_error[0] if first_error else "no output"
        LOG.warning("%s browse exited %d: %s", executable, returncode, detail)
        if "permission" in detail.lower() or "operation not permitted" in detail.lower():
            print("Hint: SDP browsing may require root or an active adapter connection.")
    records = parse_sdptool_output(stdout)
    print(f"Target : {target.upper()}")
    print(f"Records: {len(records)}")
    if not records:
        tail = (stderr or stdout).strip()
        if tail:
            print(f"Output : {tail.splitlines()[0]}")
        print("CONTINUITY_MSG_SPP: not found (no SDP records parsed)")
        return False

    header = f"  {'HANDLE':<9} {'CHAN':<5} {'PSM':<5} NAME"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for record in records:
        channel = "-" if record.rfcomm_channel is None else str(record.rfcomm_channel)
        psm = "-" if record.psm is None else str(record.psm)
        name = record.name or "(no service name)"
        print(f"  {record.handle:<9} {channel:<5} {psm:<5} {name[:48]}")

    matches = [record for record in records if CONTINUITY_UUID in record.uuids]
    if not matches:
        print("\nCONTINUITY_MSG_SPP: not found")
        for record in records:
            if "serial" in record.name.lower() or "spp" in record.name.lower():
                print(
                    f"Note: serial-looking record {record.handle} "
                    f"({record.name}) on channel {record.rfcomm_channel}"
                )
        return True

    record = matches[0]
    print(f"\nCONTINUITY_MSG_SPP: FOUND in {record.handle}")
    if record.rfcomm_channel is not None:
        print(f"RFCOMM channel    : {record.rfcomm_channel}")
    else:
        print("RFCOMM channel    : not advertised in this SDP record")
    if record.psm is not None:
        print(f"L2CAP PSM         : {record.psm}")
    return True


# ---------------------------------------------------------------------------
# BLE scan
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class BleObservation:
    address: str
    name: str | None
    rssi: int | None
    first_seen: datetime
    last_seen: datetime
    count: int
    manufacturer_data: bytes | None
    frame: McfFrame | None
    error: str | None


def record_advertisement(
    observations: dict[str, BleObservation],
    device: Any,
    advertisement: Any,
) -> None:
    manufacturer = getattr(advertisement, "manufacturer_data", None) or {}
    data = manufacturer.get(COMPANY_ID)
    if data is None:
        return
    data = bytes(data)
    now = datetime.now()
    address = getattr(device, "address", "unknown")
    frame: McfFrame | None = None
    error: str | None = None
    try:
        frame = parse_mcf_frame(data)
    except ValueError as exc:
        error = str(exc)

    current = observations.get(address)
    if current is None:
        observations[address] = BleObservation(
            address=address,
            name=getattr(device, "name", None) or getattr(advertisement, "local_name", None),
            rssi=getattr(advertisement, "rssi", None),
            first_seen=now,
            last_seen=now,
            count=1,
            manufacturer_data=data,
            frame=frame,
            error=error,
        )
        return
    current.last_seen = now
    current.count += 1
    current.rssi = getattr(advertisement, "rssi", None)
    current.manufacturer_data = data
    if frame is not None:
        current.frame = frame
        current.error = None
    elif current.frame is None:
        current.error = error
    if not current.name:
        current.name = getattr(device, "name", None) or getattr(advertisement, "local_name", None)


def print_ble_table(observations: list[BleObservation]) -> None:
    header = (
        f"{'ADDRESS':<17} {'NAME':<22} {'RSSI':>4} {'VER':<4} {'SUB':<5} "
        f"{'FLAGS':<13} {'DEV':<4} {'AUDIO':<18} {'WEAR':<4} TLV"
    )
    print(header)
    print("-" * len(header))
    for observation in observations:
        frame = observation.frame
        if frame is None:
            rssi_text = "-" if observation.rssi is None else str(observation.rssi)
            print(
                f"{observation.address:<17} {(observation.name or ''):<22} "
                f"{rssi_text:>4} "
                f"{'-':<4} {'-':<5} {'-':<13} {'-':<4} {'undecodable':<18} {'-':<4} {observation.error or ''}"
            )
            continue
        flags = (
            ("E" if frame.extended else "-")
            + ("S" if frame.secondary else "-")
            + f" sub={frame.sub_type}"
        )
        _, state_label = frame.audio_state
        wear = "-" if frame.wearing is None else ("yes" if frame.wearing else "no")
        name = (observation.name or "")[:22]
        rssi_text = "-" if observation.rssi is None else str(observation.rssi)
        print(
            f"{observation.address:<17} {name:<22} "
            f"{rssi_text:>4} "
            f"0x{frame.version:02x} 0x{frame.subtype:02x} "
            f"{flags:<13} 0x{frame.device_type:x}  {state_label[:18]:<18} {wear:<4} {len(frame.tlvs)}"
        )


def print_ble_details(observations: list[BleObservation]) -> None:
    for index, observation in enumerate(observations):
        print(f"\n[{index}] {observation.address}  {observation.name or '(unnamed)'}")
        print(
            f"    seen={observation.count}x first={observation.first_seen:%H:%M:%S} "
            f"last={observation.last_seen:%H:%M:%S} rssi={observation.rssi}"
        )
        if observation.frame is None:
            print(f"    raw     : {hex_preview(observation.manufacturer_data or b'', 60)}")
            print(f"    error   : {observation.error}")
            continue
        for line in format_frame_detail(observation.frame):
            print(f"    {line}")


async def probe_ble(args: argparse.Namespace) -> bool:
    try:
        from bleak import BleakScanner
    except ImportError as exc:
        LOG.error("bleak is not installed: %s", exc)
        return False

    print(f"\n== BLE scan ({args.duration:.0f}s, company ID 0x{COMPANY_ID:04x}) ==")
    observations: dict[str, BleObservation] = {}

    def callback(device: Any, advertisement: Any) -> None:
        try:
            record_advertisement(observations, device, advertisement)
        except Exception:  # A bad advertisement must not stop the scan.
            LOG.exception("failed to process a BLE advertisement")

    try:
        scanner = BleakScanner(detection_callback=callback, scanning_mode="active")
        async with scanner:
            await asyncio.sleep(args.duration)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        LOG.error("BLE scan failed: %s: %s", type(exc).__name__, exc)
        return False

    ordered = sorted(observations.values(), key=lambda item: item.address)
    print(f"Devices with company 0x{COMPANY_ID:04x} data: {len(ordered)}")
    if not ordered:
        print("No matching advertisements. Keep the phone unlocked with the Auto Switch app active.")
        return True
    print()
    print_ble_table(ordered)
    print_ble_details(ordered)
    return True


# ---------------------------------------------------------------------------
# btmgmt adapter summary
# ---------------------------------------------------------------------------


def run_btmgmt(command: str, timeout: float = 8.0) -> tuple[int, str, str]:
    executable = shutil.which("btmgmt")
    if not executable:
        return 127, "", "btmgmt not found in PATH"
    try:
        completed = subprocess.run(
            [executable, command],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"btmgmt {command} timed out after {timeout:.1f}s"
    except OSError as exc:
        return 126, "", f"cannot run btmgmt: {exc}"
    return completed.returncode, strip_ansi(completed.stdout), strip_ansi(completed.stderr)


def print_btmgmt_summary(timeout: float) -> None:
    print("\n== Adapter advertising features (btmgmt) ==")
    returncode, stdout, stderr = run_btmgmt("info", timeout)
    if returncode != 0:
        detail = (stderr or stdout).strip().splitlines()
        print(f"btmgmt info: unavailable (exit {returncode})")
        if detail:
            print(f"  {detail[0]}")
            if "permission" in detail[0].lower():
                print("  Hint: btmgmt usually needs root. Run with sudo for adapter settings.")
    else:
        for line in stdout.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith(
                ("supported settings:", "current settings:", "features:", "name:", "short name:")
            ):
                print(f"  {stripped}")
        current = next(
            (line for line in stdout.splitlines() if line.strip().lower().startswith("current settings:")),
            "",
        )
        advertising = "advertising" in current.lower()
        print(f"  LE advertising   : {'enabled in current settings' if advertising else 'not shown as enabled'}")

    returncode, stdout, stderr = run_btmgmt("advinfo", timeout)
    print(f"  btmgmt advinfo   : exit {returncode}")
    if returncode == 0:
        for line in stdout.splitlines()[:12]:
            if line.strip():
                print(f"    {line.strip()}")
    else:
        detail = (stderr or stdout).strip().splitlines()
        if detail:
            print(f"    {detail[0]}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Probe Samsung MCF SDP and BLE transports for Auto Switch.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--mac", help="Bluetooth address of the Samsung phone")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--ble-only", action="store_true", help="skip the SDP probes")
    mode.add_argument("--sdp-only", action="store_true", help="skip the BLE scan")
    parser.add_argument("--duration", type=float, default=30.0, help="BLE scan time in seconds")
    parser.add_argument("--timeout", type=float, default=15.0, help="D-Bus and sdptool timeout in seconds")
    parser.add_argument(
        "--connect",
        action="store_true",
        help="call BlueZ Device1.Connect once to resolve services",
    )
    parser.add_argument("--no-sdptool", action="store_true", help="skip the sdptool fallback")
    parser.add_argument("--debug", action="store_true", help="verbose logging")
    parser.add_argument("--log-json", action="store_true", help="write log lines as JSON")
    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.mac and not MAC_RE.match(args.mac):
        parser.error(f"--mac must look like AA:BB:CC:DD:EE:FF (got {args.mac!r})")
    if args.mac:
        args.mac = args.mac.upper()
    if args.duration <= 0:
        parser.error("--duration must be greater than zero")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")


async def run(args: argparse.Namespace) -> int:
    sdp_ok = False
    ble_ok = False
    device: BluezDevice | None = None

    if not args.ble_only:
        try:
            sdp_ok, device = await probe_dbus_sdp(args.mac, args)
        except Exception:
            LOG.exception("unexpected D-Bus SDP probe failure")
        try:
            sdp_ok = probe_sdptool(device, args.mac, args) or sdp_ok
        except Exception:
            LOG.exception("unexpected sdptool probe failure")

    if not args.sdp_only:
        try:
            print_btmgmt_summary(args.timeout)
            ble_ok = await probe_ble(args)
        except Exception:
            LOG.exception("unexpected BLE probe failure")

    if args.ble_only:
        return 0 if ble_ok else 1
    if args.sdp_only:
        return 0 if sdp_ok else 1
    return 0 if (sdp_ok or ble_ok) else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)
    configure_logging(args.debug, args.log_json)
    install_excepthook()
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        LOG.info("interrupted")
        return 130
    except Exception:
        LOG.exception("probe failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
