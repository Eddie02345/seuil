#!/usr/bin/env python3
"""Correlate Samsung Auto Switch events from HCI captures.

Reads an Android ``btsnoop_hci.log`` (btsnoop format) and an optional Linux
``btmon`` text capture, then prints a chronological timeline of:

* BLE advertisements that carry Samsung manufacturer data (company 0x0075),
  decoded with the MCF frame layout from ``docs/PROTOCOL_SPEC.md``.
* RFCOMM traffic on the channel that serves ``CONTINUITY_MSG_SPP``.
* AVDTP stream setup, start, suspend, close, and abort events (A2DP).
* L2CAP channel setup and HCI connection events that bracket the above.

Correlation is time based: A2DP transitions are annotated with the BLE, SPP,
and connection events that fall inside a configurable window. Capture times are
shown in local time. btsnoop timestamps are stored as microseconds since
0000-01-01 and are converted to local time, which matches btmon's local
timestamps on the capture host.

Usage:
    python3 dissect_autoswitch.py <btsnoop_hci.log> [btmon_output.txt]
                                  [--output timeline.html] [--window 2.0]
"""

from __future__ import annotations

import argparse
import bisect
import html
import json
import logging
import re
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

COMPANY_ID = 0x0075
CONTINUITY_UUID_BYTES = bytes.fromhex("3a622e58c0354a26928c5601dde7c657")
CONTINUITY_UUID_BYTES_LE = CONTINUITY_UUID_BYTES[::-1]
BTSNOOP_MAGIC = b"btsnoop\x00"
BTSNOOP_EPOCH_DELTA_US = 62_135_596_800_000_000
MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_JOINED_HEX_BYTES = 256 * 1024

PSM_NAMES = {
    0x0001: "SDP",
    0x0003: "RFCOMM",
    0x0017: "AVCTP",
    0x0019: "AVDTP",
    0x0004: "ATT",
    0x0006: "SMP",
}
AVDTP_SIGNALS = {
    0x01: "Discover",
    0x02: "Get Capabilities",
    0x03: "Set Configuration",
    0x04: "Get Configuration",
    0x05: "Reconfigure",
    0x06: "Open",
    0x07: "Start",
    0x08: "Close",
    0x09: "Suspend",
    0x0A: "Abort",
    0x0B: "Security Control",
}
AVDTP_INTERESTING = {0x03, 0x06, 0x07, 0x08, 0x09, 0x0A}
RFCOMM_CONTROLS = {0x2F: "SABM", 0x3F: "SABM", 0x63: "UA", 0x73: "UA", 0x43: "DISC", 0x0F: "DM", 0xEF: "UIH"}
MCF_OPCODE_CANDIDATES = (0xAF, 0x73, 0x77, 0x1B)

LOG = logging.getLogger("dissect")

BTMON_TS_RE = re.compile(
    r"^\s*(?:[@<>#*]\s*)?(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?"
)
BTMON_ADDR_RE = re.compile(r"Address:\s*((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})")
BTMON_RSSI_RE = re.compile(r"RSSI:\s*(-?\d+)")
BTMON_PSM_RE = re.compile(r"PSM:\s*(\d+)")
BTMON_SCID_RE = re.compile(r"Source CID:\s*(\d+)")
BTMON_DCID_RE = re.compile(r"Destination CID:\s*(\d+)")
BTMON_DLCI_RE = re.compile(r"dlci\s+(\d+)", re.IGNORECASE)
BTMON_HANDLE_RE = re.compile(r"ACL Data[^\n]*?Handle\s+(\d+)")
BTMON_AVDTP_RE = re.compile(r"AVDTP:\s*([A-Za-z ]+?)\s*\(0x([0-9a-fA-F]+)\)")
BTMON_HEX_CONT_RE = re.compile(r"^\s+([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)\s*$")
UUID_TEXT_RE = re.compile(
    r"3a622e58[- ]?c035[- ]?4a26[- ]?928c[- ]?5601[- ]?dde7[- ]?c657",
    re.IGNORECASE,
)



# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


class JsonLogFormatter(logging.Formatter):
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
    def hook(exc_type: type[BaseException], exc: BaseException, tb: Any) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc, tb)
            return
        LOG.critical("unhandled exception", exc_info=(exc_type, exc, tb))

    sys.excepthook = hook


# ---------------------------------------------------------------------------
# MCF advertisement decoder (same layout as probe_sdp_and_ble.py)
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
        return self.raw[9] if len(self.raw) > 9 else None

    @property
    def audio_state(self) -> tuple[int, str]:
        ns = self.ns
        if ns is None:
            return 2, "unknown"
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


def parse_mcf_frame(data: bytes) -> McfFrame:
    if len(data) < 4:
        raise ValueError(f"manufacturer data too short ({len(data)} bytes)")
    flags = data[2]
    issues: list[str] = []
    if data[0] != 0x02:
        issues.append(f"version 0x{data[0]:02x} != 0x02")
    if data[1] != 0x18:
        issues.append(f"subtype 0x{data[1]:02x} != 0x18")
    if flags & 0x80 and len(data) < 21:
        issues.append("extended flag with <21 bytes")
    if flags & 0x40 and len(data) < 18:
        issues.append("secondary flag with <18 bytes")

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
            issues.append(f"truncated TLV type {record_type} at {offset}")
            tlvs.append(Tlv(record_type, data[offset + 1 :]))
            break
        tlvs.append(Tlv(record_type, data[offset + 1 : end]))
        offset = end

    return McfFrame(
        raw=data,
        version=data[0],
        subtype=data[1],
        flags=flags,
        device_type=(data[3] >> 4) & 0x0F,
        device_flags=data[3] & 0x0F,
        account=data[4:13],
        tlvs=tlvs,
        issues=issues,
    )


def frame_to_details(frame: McfFrame) -> dict[str, Any]:
    state_number, state_label = frame.audio_state
    return {
        "version": f"0x{frame.version:02x}",
        "subtype": f"0x{frame.subtype:02x}",
        "extended": frame.extended,
        "secondary": frame.secondary,
        "sub_type": frame.sub_type,
        "device_type": frame.device_type,
        "device_flags": frame.device_flags,
        "account": frame.account.hex(),
        "ns": frame.ns,
        "audio_state": state_number,
        "audio_label": state_label,
        "wearing": frame.wearing,
        "tlvs": [
            {
                "type": tlv.type,
                "name": tlv.name,
                "length": len(tlv.payload),
                "payload": tlv.payload.hex(),
            }
            for tlv in frame.tlvs
        ],
        "issues": frame.issues,
    }


# ---------------------------------------------------------------------------
# Byte helpers
# ---------------------------------------------------------------------------


def parse_ad_structures(data: bytes) -> Iterable[tuple[int, bytes]]:
    offset = 0
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            continue
        end = offset + 1 + length
        if end > len(data):
            return
        yield data[offset + 1], data[offset + 2 : end]
        offset = end


def manufacturer_data_from_ad(data: bytes, company: int = COMPANY_ID) -> bytes | None:
    for ad_type, payload in parse_ad_structures(data):
        if ad_type == 0xFF and len(payload) >= 2:
            if int.from_bytes(payload[:2], "little") == company:
                return payload[2:]
    return None


def format_address(raw: bytes) -> str:
    return ":".join(f"{byte:02X}" for byte in reversed(raw))


def find_rfcomm_channel(data: bytes) -> int | None:
    marker = b"\x19\x00\x03\x08"
    index = data.find(marker)
    while index != -1:
        if index + 4 < len(data):
            channel = data[index + 4]
            if 1 <= channel <= 30:
                return channel
        index = data.find(marker, index + 1)
    return None


def scan_sdp_payload(payload: bytes) -> tuple[bool, int | None]:
    found = CONTINUITY_UUID_BYTES in payload or CONTINUITY_UUID_BYTES_LE in payload
    channel = find_rfcomm_channel(payload) if found else None
    return found, channel


def looks_binary(data: bytes) -> bool:
    if not data:
        return False
    printable = sum(1 for byte in data if 32 <= byte < 127 or byte in (9, 10, 13))
    return printable / len(data) < 0.7


def btmon_hex_fields(block: list[str]) -> bytes:
    """Join every Data:/Payload: field in a btmon block, with continuations."""
    fields: list[list[str]] = []
    current: list[str] | None = None
    for line in block:
        match = re.match(r"^\s*(?:Data|Payload):\s*(.*)$", line)
        if match:
            current = [match.group(1)]
            fields.append(current)
            continue
        if current is not None:
            continuation = BTMON_HEX_CONT_RE.match(line)
            if continuation:
                current.append(continuation.group(1))
                continue
        current = None
    blobs: list[bytes] = []
    for parts in fields:
        text = re.sub(r"\s+", "", " ".join(parts))
        if text and len(text) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", text):
            blobs.append(bytes.fromhex(text))
    return b"".join(blobs)


def btsnoop_timestamp(timestamp_us: int) -> datetime:
    """Convert a btsnoop timestamp to local time.

    btsnoop stores microseconds since 0000-01-01. Some writers use Unix
    microseconds instead, so both interpretations are checked.
    """
    try:
        candidate = datetime.fromtimestamp((timestamp_us - BTSNOOP_EPOCH_DELTA_US) / 1_000_000)
    except (OverflowError, OSError, ValueError):
        candidate = None
    if candidate is not None and 1990 <= candidate.year <= 2100:
        return candidate
    try:
        unix_candidate = datetime.fromtimestamp(timestamp_us / 1_000_000)
    except (OverflowError, OSError, ValueError):
        unix_candidate = None
    if unix_candidate is not None and 1990 <= unix_candidate.year <= 2100:
        return unix_candidate
    LOG.warning("implausible btsnoop timestamp %d; using epoch ordering", timestamp_us)
    return datetime(1970, 1, 1)


def parse_btmon_timestamp(match: re.Match[str]) -> datetime | None:
    date_part = match.group(1)
    time_part = match.group(2)
    fraction = (match.group(3) or "0")[:6].ljust(6, "0")
    try:
        return datetime.strptime(f"{date_part} {time_part}.{fraction}", "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Event:
    timestamp: datetime | None
    source: str
    kind: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    order: int = 0
    related: list[int] = field(default_factory=list)


@dataclass
class ParseStats:
    source: str
    records: int = 0
    errors: int = 0
    timestamps: int = 0
    datalink: int | None = None
    note: str = ""


class Timeline:
    def __init__(self) -> None:
        self.events: list[Event] = []
        self.spp_channels: set[int] = set()
        self.sdp_seen: set[tuple[bool, int | None]] = set()
        self.l2cap_psm: dict[tuple[int, int], int] = {}
        self.acl_buffers: dict[tuple[int, str], bytearray] = {}
        self.dropped_rfcomm = 0
        self._order = 0

    def add(
        self,
        timestamp: datetime | None,
        source: str,
        kind: str,
        summary: str,
        details: dict[str, Any] | None = None,
    ) -> Event:
        event = Event(
            timestamp=timestamp,
            source=source,
            kind=kind,
            summary=summary,
            details=details or {},
            order=self._order,
        )
        self._order += 1
        self.events.append(event)
        return event

    # -- btsnoop ----------------------------------------------------------

    def decode_btsnoop_record(
        self,
        timestamp: datetime,
        flags: int,
        datalink: int,
        data: bytes,
    ) -> None:
        packet_type, body = hci_type_and_body(datalink, flags, data)
        if packet_type is None or not body:
            return
        direction = "rx" if flags & 0x01 else "tx"
        if packet_type == 0x01:
            self._decode_hci_command(timestamp, body, direction)
        elif packet_type == 0x04:
            self._decode_hci_event(timestamp, body, direction)
        elif packet_type == 0x02:
            self._decode_acl(timestamp, body, direction)
        # SCO and ISO packets carry no Auto Switch control traffic.

    def _decode_hci_command(self, timestamp: datetime, body: bytes, direction: str) -> None:
        if len(body) < 3:
            return
        opcode = int.from_bytes(body[0:2], "little")
        param_length = body[2]
        params = body[3 : 3 + param_length]
        if opcode == 0x0405 and len(params) >= 6:
            address = format_address(params[0:6])
            self._add_connection(
                timestamp,
                f"BR/EDR create connection to {address}",
                direction,
                {"address": address},
            )
        elif opcode == 0x0406 and len(params) >= 3:
            handle = int.from_bytes(params[0:2], "little") & 0x0FFF
            reason = params[2]
            self._add_connection(
                timestamp,
                f"Disconnect handle 0x{handle:03x} reason 0x{reason:02x}",
                direction,
                {"handle": handle, "reason": f"0x{reason:02x}"},
            )
        elif opcode == 0x200D and len(params) >= 8:
            address_type = params[5]
            address = format_address(params[6:12]) if len(params) >= 12 else "unknown"
            self._add_connection(
                timestamp,
                f"LE create connection to {address} (type {address_type})",
                direction,
                {"address": address},
            )

    def _decode_hci_event(self, timestamp: datetime, body: bytes, direction: str) -> None:
        if len(body) < 2:
            return
        event_code = body[0]
        param_length = body[1]
        params = body[2 : 2 + param_length]

        if event_code == 0x03 and len(params) >= 11:
            status = params[0]
            handle = int.from_bytes(params[1:3], "little") & 0x0FFF
            address = format_address(params[3:9])
            link_type = params[9]
            summary = (
                f"BR/EDR connected {address} (handle 0x{handle:03x}, link {link_type})"
                if status == 0
                else f"BR/EDR connect failed {address} status 0x{status:02x}"
            )
            self._add_connection(
                timestamp,
                summary,
                direction,
                {"address": address, "handle": handle, "status": status, "link_type": link_type},
            )
            return

        if event_code == 0x05 and len(params) >= 4:
            status = params[0]
            handle = int.from_bytes(params[1:3], "little") & 0x0FFF
            reason = params[3]
            self._add_connection(
                timestamp,
                f"Disconnected handle 0x{handle:03x} reason 0x{reason:02x}",
                direction,
                {"handle": handle, "reason": f"0x{reason:02x}", "status": status},
            )
            return

        if event_code != 0x3E or not params:
            return
        subevent = params[0]
        payload = params[1:]
        if subevent == 0x01 and len(payload) >= 11:
            status = payload[0]
            handle = int.from_bytes(payload[1:3], "little") & 0x0FFF
            address = format_address(payload[5:11])
            self._add_connection(
                timestamp,
                f"LE connected {address} (handle 0x{handle:03x})"
                if status == 0
                else f"LE connect failed {address} status 0x{status:02x}",
                direction,
                {"address": address, "handle": handle, "status": status},
            )
        elif subevent == 0x02:
            self._decode_adv_reports(timestamp, payload, direction, extended=False)
        elif subevent == 0x0D:
            self._decode_adv_reports(timestamp, payload, direction, extended=True)

    def _decode_adv_reports(
        self,
        timestamp: datetime,
        payload: bytes,
        direction: str,
        *,
        extended: bool,
    ) -> None:
        if not payload:
            return
        count = payload[0]
        offset = 1
        for _ in range(count):
            if extended:
                if len(payload) < offset + 24:
                    return
                address = format_address(payload[offset + 3 : offset + 9])
                rssi = int.from_bytes(payload[offset + 13 : offset + 14], "little", signed=True)
                data_length = payload[offset + 23]
                data = payload[offset + 24 : offset + 24 + data_length]
                offset += 24 + data_length
            else:
                if len(payload) < offset + 10:
                    return
                address = format_address(payload[offset + 2 : offset + 8])
                data_length = payload[offset + 8]
                data = payload[offset + 9 : offset + 9 + data_length]
                rssi = int.from_bytes(
                    payload[offset + 9 + data_length : offset + 10 + data_length],
                    "little",
                    signed=True,
                )
                offset += 10 + data_length
            self.add_advertisement(timestamp, address, rssi, data, direction, "btsnoop")

    def _decode_acl(self, timestamp: datetime, body: bytes, direction: str) -> None:
        if len(body) < 4:
            return
        handle_flags = int.from_bytes(body[0:2], "little")
        handle = handle_flags & 0x0FFF
        packet_boundary = (handle_flags >> 12) & 0x3
        data_length = int.from_bytes(body[2:4], "little")
        fragment = body[4 : 4 + data_length]
        if len(fragment) < data_length:
            LOG.debug("truncated ACL fragment on handle 0x%03x", handle)
            return
        self._feed_acl(timestamp, handle, packet_boundary, fragment, direction)

    def _feed_acl(
        self,
        timestamp: datetime,
        handle: int,
        packet_boundary: int,
        fragment: bytes,
        direction: str,
    ) -> None:
        buffer = self.acl_buffers.setdefault((handle, direction), bytearray())
        if packet_boundary != 0b01:
            buffer.clear()
        buffer.extend(fragment)

        while len(buffer) >= 4:
            cid = int.from_bytes(buffer[0:2], "little")
            length = int.from_bytes(buffer[2:4], "little")
            if length > MAX_JOINED_HEX_BYTES:
                LOG.debug("implausible L2CAP length %d on handle 0x%03x", length, handle)
                buffer.clear()
                return
            if len(buffer) < 4 + length:
                return
            payload = bytes(buffer[4 : 4 + length])
            del buffer[: 4 + length]
            self._handle_l2cap(timestamp, handle, cid, payload, direction)

    def _handle_l2cap(
        self,
        timestamp: datetime,
        handle: int,
        cid: int,
        payload: bytes,
        direction: str,
    ) -> None:
        if cid == 0x0001:
            self._handle_signaling(timestamp, handle, payload, direction)
            return
        psm = self.l2cap_psm.get((handle, cid))
        if psm == 0x0001:
            self._handle_sdp(timestamp, handle, payload, direction)
        elif psm == 0x0003:
            self._handle_rfcomm_l2cap(timestamp, handle, payload, direction)
        elif psm == 0x0019:
            self._handle_avdtp(timestamp, handle, payload, direction)

    def _handle_signaling(
        self,
        timestamp: datetime,
        handle: int,
        payload: bytes,
        direction: str,
    ) -> None:
        if len(payload) < 4:
            return
        code = payload[0]
        length = int.from_bytes(payload[2:4], "little")
        body = payload[4 : 4 + length]

        if code == 0x02 and len(body) >= 4:
            psm = int.from_bytes(body[0:2], "little")
            source_cid = int.from_bytes(body[2:4], "little")
            self.l2cap_psm[(handle, source_cid)] = psm
            if psm in (0x0001, 0x0003, 0x0019):
                self.add(
                    timestamp,
                    "btsnoop",
                    "l2cap",
                    f"L2CAP connect request {psm_name(psm)} (source CID {source_cid})",
                    {"psm": psm, "psm_name": psm_name(psm), "cid": source_cid, "direction": direction},
                )
        elif code == 0x03 and len(body) >= 8:
            destination_cid = int.from_bytes(body[0:2], "little")
            source_cid = int.from_bytes(body[2:4], "little")
            result = int.from_bytes(body[4:6], "little")
            psm = self.l2cap_psm.get((handle, destination_cid))
            if psm is not None:
                self.l2cap_psm[(handle, source_cid)] = psm
            if psm in (0x0001, 0x0003, 0x0019):
                self.add(
                    timestamp,
                    "btsnoop",
                    "l2cap",
                    f"L2CAP connect response {psm_name(psm)} "
                    f"(CID {source_cid}, result 0x{result:04x})",
                    {
                        "psm": psm,
                        "psm_name": psm_name(psm),
                        "cid": source_cid,
                        "result": result,
                        "direction": direction,
                    },
                )
        elif code == 0x06 and len(body) >= 4:
            destination_cid = int.from_bytes(body[0:2], "little")
            psm = self.l2cap_psm.get((handle, destination_cid))
            if psm == 0x0019:
                self.add(
                    timestamp,
                    "btsnoop",
                    "a2dp",
                    "AVDTP L2CAP channel disconnected",
                    {"psm": psm, "cid": destination_cid, "direction": direction},
                )
            elif psm == 0x0003:
                self.add(
                    timestamp,
                    "btsnoop",
                    "l2cap",
                    "RFCOMM L2CAP channel disconnected",
                    {"psm": psm, "cid": destination_cid, "direction": direction},
                )
        elif code == 0x14 and len(body) >= 8:
            psm = int.from_bytes(body[0:2], "little")
            source_cid = int.from_bytes(body[2:4], "little")
            self.l2cap_psm[(handle, source_cid)] = psm
            if psm in (0x0001, 0x0003, 0x0019):
                self.add(
                    timestamp,
                    "btsnoop",
                    "l2cap",
                    f"LE L2CAP connect request {psm_name(psm)} (source CID {source_cid})",
                    {"psm": psm, "psm_name": psm_name(psm), "cid": source_cid, "direction": direction},
                )
        elif code == 0x15 and len(body) >= 8:
            destination_cid = int.from_bytes(body[0:2], "little")
            source_cid = int.from_bytes(body[2:4], "little")
            result = int.from_bytes(body[4:6], "little")
            psm = self.l2cap_psm.get((handle, destination_cid))
            if psm is not None:
                self.l2cap_psm[(handle, source_cid)] = psm
            if psm in (0x0001, 0x0003, 0x0019):
                self.add(
                    timestamp,
                    "btsnoop",
                    "l2cap",
                    f"LE L2CAP connect response {psm_name(psm)} "
                    f"(CID {source_cid}, result 0x{result:04x})",
                    {
                        "psm": psm,
                        "psm_name": psm_name(psm),
                        "cid": source_cid,
                        "result": result,
                        "direction": direction,
                    },
                )

    def _handle_sdp(
        self,
        timestamp: datetime,
        handle: int,
        payload: bytes,
        direction: str,
    ) -> None:
        if not payload:
            return
        pdu_id = payload[0]
        found, channel = scan_sdp_payload(payload)
        if channel is not None:
            self.spp_channels.add(channel)
        if not found and channel is None:
            return
        key = (found, channel)
        if key in self.sdp_seen:
            return
        self.sdp_seen.add(key)
        if found and channel is not None:
            summary = f"SDP record references CONTINUITY_MSG_SPP, RFCOMM channel {channel}"
        elif found:
            summary = "SDP traffic references CONTINUITY_MSG_SPP (channel not parsed)"
        else:
            summary = f"SDP response advertises RFCOMM channel {channel}"
        self.add(
            timestamp,
            "btsnoop",
            "sdp",
            summary,
            {
                "pdu_id": pdu_id,
                "uuid_found": found,
                "channel": channel,
                "length": len(payload),
                "direction": direction,
            },
        )

    def _handle_avdtp(
        self,
        timestamp: datetime,
        handle: int,
        payload: bytes,
        direction: str,
    ) -> None:
        if len(payload) < 2:
            return
        header = payload[0]
        message_type = header & 0x03
        packet_type = (header >> 2) & 0x03
        if packet_type in (0x01, 0x02):
            return
        signal_id = payload[1]
        if signal_id not in AVDTP_INTERESTING:
            return
        name = AVDTP_SIGNALS.get(signal_id, f"0x{signal_id:02x}")
        message_label = "command" if message_type == 0 else "response"
        self.add(
            timestamp,
            "btsnoop",
            "a2dp",
            f"AVDTP {name} ({message_label})",
            {
                "signal": name,
                "signal_id": signal_id,
                "message_type": message_label,
                "handle": handle,
                "payload": payload.hex(),
                "direction": direction,
            },
        )

    def _handle_rfcomm_l2cap(
        self,
        timestamp: datetime,
        handle: int,
        payload: bytes,
        direction: str,
    ) -> None:
        parsed = parse_rfcomm_frame(payload)
        if parsed is None:
            return
        dlci, control, frame_payload = parsed
        self.handle_rfcomm_payload(
            timestamp, "btsnoop", dlci >> 1, dlci, control, frame_payload, direction
        )

    # -- btmon ------------------------------------------------------------

    def handle_btmon_adv(self, block: list[str], timestamp: datetime | None) -> None:
        text = "\n".join(block)
        addresses = BTMON_ADDR_RE.findall(text)
        if not addresses:
            return
        raw = btmon_hex_fields(block)
        if not raw:
            return
        if len(raw) > MAX_JOINED_HEX_BYTES:
            LOG.debug("advertising data too large (%d bytes)", len(raw))
            return
        rssi_match = BTMON_RSSI_RE.search(text)
        rssi = int(rssi_match.group(1)) if rssi_match else None
        self.add_advertisement(
            timestamp,
            addresses[0].upper(),
            rssi,
            raw,
            "unknown",
            "btmon",
        )

    def handle_btmon_l2cap(self, block: list[str], timestamp: datetime | None, handle: int | None) -> None:
        text = "\n".join(block)

        psm_match = BTMON_PSM_RE.search(text)
        psm = int(psm_match.group(1)) if psm_match else None
        source_match = BTMON_SCID_RE.search(text)
        destination_match = BTMON_DCID_RE.search(text)
        source_cid = int(source_match.group(1)) if source_match else None
        destination_cid = int(destination_match.group(1)) if destination_match else None
        handle_key = handle if handle is not None else -1

        if "Connection Request" in text or "LE Credit Based Connection Request" in text:
            if psm is not None and source_cid is not None:
                self.l2cap_psm[(handle_key, source_cid)] = psm
            if psm in (0x0001, 0x0003, 0x0019):
                self.add(
                    timestamp,
                    "btmon",
                    "l2cap",
                    f"L2CAP connect request {psm_name(psm)} (source CID {source_cid})",
                    {"psm": psm, "psm_name": psm_name(psm), "cid": source_cid},
                )
        elif "Connection Response" in text or "LE Credit Based Connection Response" in text:
            if destination_cid is not None:
                psm = self.l2cap_psm.get((handle_key, destination_cid), psm)
            if psm is not None and source_cid is not None:
                self.l2cap_psm[(handle_key, source_cid)] = psm
            if psm in (0x0001, 0x0003, 0x0019):
                self.add(
                    timestamp,
                    "btmon",
                    "l2cap",
                    f"L2CAP connect response {psm_name(psm)} (CID {source_cid})",
                    {"psm": psm, "psm_name": psm_name(psm), "cid": source_cid},
                )
        elif "Disconnection Request" in text:
            cid = destination_cid
            psm = self.l2cap_psm.get((handle_key, cid)) if cid is not None else None
            if psm == 0x0019:
                self.add(
                    timestamp,
                    "btmon",
                    "a2dp",
                    "AVDTP L2CAP channel disconnected",
                    {"psm": psm, "cid": cid},
                )
            elif psm == 0x0003:
                self.add(
                    timestamp,
                    "btmon",
                    "l2cap",
                    "RFCOMM L2CAP channel disconnected",
                    {"psm": psm, "cid": cid},
                )

        found, channel = btmon_find_sdp(text, btmon_hex_fields(block))
        if channel is not None:
            self.spp_channels.add(channel)
        if not found and channel is None:
            return
        key = (found, channel)
        if key in self.sdp_seen:
            return
        self.sdp_seen.add(key)
        if found and channel is not None:
            summary = f"SDP data references CONTINUITY_MSG_SPP, RFCOMM channel {channel}"
        elif found:
            summary = "SDP data references CONTINUITY_MSG_SPP (channel not parsed)"
        else:
            summary = f"SDP data advertises RFCOMM channel {channel}"
        self.add(
            timestamp,
            "btmon",
            "sdp",
            summary,
            {"uuid_found": found, "channel": channel, "block_lines": len(block)},
        )

    def handle_btmon_avdtp(self, block: list[str], timestamp: datetime | None, handle: int | None) -> None:
        text = "\n".join(block)
        match = BTMON_AVDTP_RE.search(text)
        if not match:
            return
        name = AVDTP_SIGNALS.get(int(match.group(2), 16), match.group(1).strip())
        signal_id = int(match.group(2), 16)
        if signal_id not in AVDTP_INTERESTING:
            return
        if "Response" in text:
            message_label = "response"
        elif "Command" in text:
            message_label = "command"
        else:
            message_label = "unknown"
        self.add(
            timestamp,
            "btmon",
            "a2dp",
            f"AVDTP {name} ({message_label})",
            {
                "signal": name,
                "signal_id": signal_id,
                "message_type": message_label,
                "handle": handle,
                "raw": text[:512],
            },
        )

    def handle_btmon_rfcomm(self, block: list[str], timestamp: datetime | None, handle: int | None) -> None:
        text = "\n".join(block)
        dlci_match = BTMON_DLCI_RE.search(text)
        if not dlci_match:
            return
        dlci = int(dlci_match.group(1))
        if dlci == 0:
            return
        control_match = re.search(r"\((0x[0-9a-fA-F]{2})\)", block[0])
        control = int(control_match.group(1), 16) if control_match else 0xEF
        frame_payload = btmon_hex_fields(block)
        self.handle_rfcomm_payload(
            timestamp, "btmon", dlci >> 1, dlci, control, frame_payload, "unknown"
        )

    # -- shared RFCOMM and advertisement handling -------------------------

    def handle_rfcomm_payload(
        self,
        timestamp: datetime | None,
        source: str,
        channel: int,
        dlci: int,
        control: int,
        payload: bytes,
        direction: str,
    ) -> None:
        if channel == 0:
            return
        control_name = RFCOMM_CONTROLS.get(control, f"0x{control:02x}")
        confirmed = channel in self.spp_channels
        if self.spp_channels and not confirmed:
            self.dropped_rfcomm += 1
            LOG.debug("skip RFCOMM channel %d (SPP channels %s)", channel, sorted(self.spp_channels))
            return

        if not payload:
            if control_name in ("SABM", "UA"):
                self.add(
                    timestamp,
                    source,
                    "spp",
                    f"RFCOMM ch {channel} {control_name} (channel setup)",
                    {
                        "channel": channel,
                        "dlci": dlci,
                        "control": control_name,
                        "payload": "",
                        "payload_bytes": 0,
                        "confidence": "confirmed" if confirmed else "unconfirmed",
                        "setup": True,
                        "direction": direction,
                    },
                )
            return

        if not self.spp_channels and not looks_binary(payload):
            self.dropped_rfcomm += 1
            LOG.debug("skip printable RFCOMM channel %d payload (%d bytes)", channel, len(payload))
            return

        opcodes = [value for value in MCF_OPCODE_CANDIDATES if value in payload]
        confidence = "confirmed" if confirmed else "unconfirmed"
        summary = f"RFCOMM ch {channel} ({confidence}) {len(payload)}B"
        if opcodes:
            summary += " opcode-candidate " + ",".join(f"0x{value:02x}" for value in opcodes)
        self.add(
            timestamp,
            source,
            "spp",
            summary,
            {
                "channel": channel,
                "dlci": dlci,
                "control": control_name,
                "payload": payload.hex(),
                "payload_bytes": len(payload),
                "confidence": confidence,
                "binary": looks_binary(payload),
                "opcodes": [f"0x{value:02x}" for value in opcodes],
                "direction": direction,
            },
        )

    def add_advertisement(
        self,
        timestamp: datetime | None,
        address: str,
        rssi: int | None,
        ad_data: bytes,
        direction: str,
        source: str,
    ) -> None:
        manufacturer = manufacturer_data_from_ad(ad_data)
        if manufacturer is None:
            return
        try:
            frame = parse_mcf_frame(manufacturer)
        except ValueError as exc:
            frame = None
            summary = f"{address} company 0x0075 data ({len(manufacturer)}B): {exc}"
        else:
            _, audio_label = frame.audio_state
            wear = frame.wearing
            wear_label = "?" if wear is None else ("1" if wear else "0")
            summary = (
                f"{address} MCF v{frame.version} sub=0x{frame.subtype:02x} "
                f"audio={audio_label} wear={wear_label} tlvs={len(frame.tlvs)}"
            )
        self.add(
            timestamp,
            source,
            "ble_adv",
            summary,
            {
                "address": address,
                "rssi": rssi,
                "manufacturer": manufacturer.hex(),
                "ad_data": ad_data.hex(),
                "frame": frame_to_details(frame) if frame else None,
                "direction": direction,
            },
        )

    def _add_connection(
        self,
        timestamp: datetime,
        summary: str,
        direction: str,
        details: dict[str, Any],
    ) -> None:
        payload = {"direction": direction, **details}
        self.add(timestamp, "btsnoop", "connection", summary, payload)


def hci_type_and_body(datalink: int, flags: int, data: bytes) -> tuple[int | None, bytes]:
    """Return (H4 packet type, packet body) for a btsnoop record."""
    if not data:
        return None, b""
    if datalink == 1002:
        return data[0], data[1:]
    if datalink == 1001:
        if flags & 0x02:
            return (0x01 if not (flags & 0x01) else 0x04), data
        return 0x02, data
    if data[0] in (0x01, 0x02, 0x03, 0x04, 0x05):
        return data[0], data[1:]
    if flags & 0x02:
        return (0x01 if not (flags & 0x01) else 0x04), data
    return 0x02, data


def psm_name(psm: int | None) -> str:
    if psm is None:
        return "PSM unknown"
    return f"PSM {psm} ({PSM_NAMES.get(psm, 'unknown')})"


def parse_rfcomm_frame(frame: bytes) -> tuple[int, int, bytes] | None:
    """Return (dlci, control, payload) for a full RFCOMM frame, else None."""
    if len(frame) < 3:
        return None
    address = frame[0]
    if not (address & 0x01):
        return None
    dlci = address >> 2
    control = frame[1]
    offset = 2
    length_byte = frame[offset]
    if length_byte & 0x01:
        length = length_byte >> 1
        offset += 1
    else:
        if offset + 1 >= len(frame):
            return None
        length = (length_byte >> 1) | (frame[offset + 1] << 7)
        offset += 2
    payload = frame[offset : offset + length]
    if len(payload) < length:
        return None
    return dlci, control, payload


def btmon_find_sdp(text: str, data: bytes = b"") -> tuple[bool, int | None]:
    found = bool(UUID_TEXT_RE.search(text))
    channel: int | None = None
    channel_match = re.search(r"Channel:\s*(\d+)", text)
    if found and channel_match:
        candidate = int(channel_match.group(1))
        if 1 <= candidate <= 30:
            channel = candidate
    if found and channel is None and data:
        channel = find_rfcomm_channel(data)
    return found, channel


# ---------------------------------------------------------------------------
# File parsers
# ---------------------------------------------------------------------------


def parse_btsnoop(path: Path, timeline: Timeline) -> ParseStats:
    stats = ParseStats("btsnoop")
    try:
        handle = path.open("rb")
    except OSError as exc:
        raise ValueError(f"cannot open {path}: {exc}") from exc

    with handle:
        header = handle.read(16)
        if len(header) < 16:
            raise ValueError("file is shorter than the 16-byte btsnoop header")
        if header[:8] != BTSNOOP_MAGIC:
            raise ValueError("bad btsnoop magic (not a btsnoop file)")
        version, datalink = struct.unpack(">II", header[8:16])
        stats.datalink = datalink
        stats.note = f"version {version}"

        while True:
            raw_header = handle.read(24)
            if not raw_header:
                break
            stats.records += 1
            if len(raw_header) < 24:
                stats.errors += 1
                LOG.warning("truncated btsnoop record header at record %d", stats.records)
                break
            original_length, included_length, flags, _drops, timestamp_us = struct.unpack(
                ">IIIIq", raw_header
            )
            if included_length > MAX_RECORD_BYTES:
                stats.errors += 1
                LOG.warning(
                    "record %d has implausible included length %d; stopping",
                    stats.records,
                    included_length,
                )
                break
            data = handle.read(included_length)
            if len(data) < included_length:
                stats.errors += 1
                LOG.warning("record %d payload truncated", stats.records)
                break
            if included_length != original_length:
                LOG.debug(
                    "record %d included %d of %d bytes",
                    stats.records,
                    included_length,
                    original_length,
                )
            try:
                timeline.decode_btsnoop_record(
                    btsnoop_timestamp(timestamp_us), flags, datalink, data
                )
            except Exception:
                stats.errors += 1
                LOG.exception("record %d could not be decoded", stats.records)
    return stats


def collect_btmon_block(lines: list[str], start: int) -> tuple[list[str], int]:
    base_indent = len(lines[start]) - len(lines[start].lstrip())
    block = [lines[start]]
    index = start + 1
    while index < len(lines) and len(block) < 5000:
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            block.append(line)
            index += 1
            continue
        indent = len(line) - len(line.lstrip())
        if BTMON_TS_RE.match(line) and indent <= base_indent:
            break
        if indent <= base_indent and re.match(
            r"^(?:[<>@]|HCI (?:Event|Command)|ACL Data|SCO Data|ISO Data|"
            r"L2CAP:|RFCOMM:|AVDTP:|SDP:|LE (?:Extended )?Advertising Report)",
            stripped,
        ):
            break
        block.append(line)
        index += 1
    return block, index


def parse_btmon(path: Path, timeline: Timeline) -> ParseStats:
    stats = ParseStats("btmon")
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"cannot open {path}: {exc}") from exc
    lines = text.splitlines()
    stats.records = len(lines)
    index = 0
    current_timestamp: datetime | None = None
    current_handle: int | None = None

    while index < len(lines):
        raw_line = lines[index]
        line = raw_line
        timestamp_match = BTMON_TS_RE.match(raw_line)
        if timestamp_match:
            parsed = parse_btmon_timestamp(timestamp_match)
            if parsed is not None:
                current_timestamp = parsed
                stats.timestamps += 1
            tail = raw_line[timestamp_match.end() :].strip()
            if not tail:
                index += 1
                continue
            line = tail

        handle_match = BTMON_HANDLE_RE.search(line)
        if handle_match:
            current_handle = int(handle_match.group(1))

        try:
            if "LE Advertising Report" in line or "LE Extended Advertising Report" in line:
                block, next_index = collect_btmon_block(lines, index)
                timeline.handle_btmon_adv(block, current_timestamp)
                index = next_index
                continue
            if "L2CAP:" in line or "SDP:" in line:
                block, next_index = collect_btmon_block(lines, index)
                timeline.handle_btmon_l2cap(block, current_timestamp, current_handle)
                index = next_index
                continue
            if "AVDTP:" in line:
                block, next_index = collect_btmon_block(lines, index)
                timeline.handle_btmon_avdtp(block, current_timestamp, current_handle)
                index = next_index
                continue
            if "RFCOMM:" in line:
                block, next_index = collect_btmon_block(lines, index)
                timeline.handle_btmon_rfcomm(block, current_timestamp, current_handle)
                index = next_index
                continue
        except Exception:
            stats.errors += 1
            LOG.exception("btmon parse error near line %d", index + 1)
        index += 1

    if stats.timestamps == 0 and stats.records:
        stats.note = "no timestamps found"
        LOG.warning("btmon file has no timestamps; synthetic times will be assigned")
    return stats


# ---------------------------------------------------------------------------
# Post-processing
# ---------------------------------------------------------------------------


def assign_missing_timestamps(events: list[Event]) -> int:
    missing = [event for event in events if event.timestamp is None]
    if not missing:
        return 0
    known = [event.timestamp for event in events if event.timestamp is not None]
    anchor = (max(known) + timedelta(seconds=1)) if known else datetime.now()
    offset = 0
    for event in events:
        if event.timestamp is None:
            event.timestamp = anchor + timedelta(milliseconds=offset)
            event.details["synthetic_time"] = True
            offset += 1
    LOG.warning(
        "assigned synthetic timestamps to %d event(s); placed after the last known event",
        len(missing),
    )
    return len(missing)


def filter_spp_events(events: list[Event], channels: set[int]) -> tuple[list[Event], int]:
    if not channels:
        return events, 0
    kept: list[Event] = []
    dropped = 0
    for event in events:
        if event.kind == "spp" and event.details.get("channel") not in channels:
            dropped += 1
            continue
        kept.append(event)
    return kept, dropped


def dedupe_advertisements(events: list[Event], window: float) -> tuple[list[Event], int]:
    kept: list[Event] = []
    last_seen: dict[tuple[str, str], Event] = {}
    suppressed = 0
    for event in events:
        if event.kind != "ble_adv" or event.timestamp is None:
            kept.append(event)
            continue
        key = (str(event.details.get("address")), str(event.details.get("manufacturer")))
        previous = last_seen.get(key)
        if previous is not None and previous.timestamp is not None:
            delta = (event.timestamp - previous.timestamp).total_seconds()
            if 0 <= delta <= window:
                previous.details["repeats"] = int(previous.details.get("repeats", 1)) + 1
                suppressed += 1
                continue
        last_seen[key] = event
        kept.append(event)
    return kept, suppressed


def correlate(events: list[Event], window_seconds: float) -> int:
    if not events:
        return 0
    events.sort(key=lambda event: (event.timestamp, event.order))
    times = [event.timestamp for event in events]
    delta = timedelta(seconds=window_seconds)
    cross_source = 0
    for index, event in enumerate(events):
        if event.kind != "a2dp" or event.timestamp is None:
            continue
        low = bisect.bisect_left(times, event.timestamp - delta)
        high = bisect.bisect_right(times, event.timestamp + delta)
        event.related = [
            other
            for other in range(low, high)
            if other != index and not events[other].details.get("synthetic_time")
        ]
        if any(events[other].source != event.source for other in event.related):
            cross_source += 1
    return cross_source


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def summary_lines(
    events: list[Event],
    stats: dict[str, ParseStats],
    timeline: Timeline,
    cross_source: int,
    suppressed: int,
    dropped_spp: int,
    window: float,
    synthetic: int = 0,
) -> list[str]:
    counts = Counter(event.kind for event in events)
    lines = ["Capture summary"]
    for name, stat in stats.items():
        unit = "lines" if name == "btmon" else "records"
        detail = f"  {name:<8}: {stat.records} {unit}"
        if stat.datalink is not None:
            detail += f", datalink {stat.datalink}"
        if stat.note:
            detail += f", {stat.note}"
        if stat.errors:
            detail += f", {stat.errors} parse error(s)"
        lines.append(detail)
    if counts:
        event_summary = ", ".join(f"{kind} {count}" for kind, count in sorted(counts.items()))
        lines.append(f"  events  : {event_summary}")
    else:
        lines.append("  events  : none")
    channels = ", ".join(str(channel) for channel in sorted(timeline.spp_channels)) or "not identified"
    lines.append(f"  SPP RFCOMM channel(s): {channels}")
    a2dp_transitions = counts.get("a2dp", 0)
    lines.append(
        f"  A2DP transitions: {a2dp_transitions} "
        f"({cross_source} with cross-source events within {window:.1f}s)"
    )
    if dropped_spp:
        lines.append(f"  RFCOMM frames filtered out: {dropped_spp}")
    if suppressed:
        lines.append(f"  Repeated BLE advertisements collapsed: {suppressed}")
    if timeline.dropped_rfcomm:
        lines.append(f"  RFCOMM frames skipped during parsing: {timeline.dropped_rfcomm}")
    if synthetic:
        lines.append(f"  Events with synthetic timestamps: {synthetic} (marked with ~)")
    return lines


def render_text(
    events: list[Event],
    summary: list[str],
    *,
    verbose: bool,
) -> str:
    lines = ["Samsung Auto Switch timeline", ""]
    if not events:
        lines.append("No matching events.")
    else:
        header = f"{'TIMESTAMP':<23}  {'SOURCE':<8}  {'KIND':<10}  SUMMARY"
        lines.append(header)
        lines.append("-" * len(header))
        for event in events:
            timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if event.timestamp else "?"
            if event.details.get("synthetic_time"):
                timestamp = "~" + timestamp
            lines.append(f"{timestamp:<23}  {event.source:<8}  {event.kind:<10}  {event.summary}")
            if verbose and event.details:
                for key, value in sorted(event.details.items()):
                    if key in ("frame", "tlvs"):
                        continue
                    lines.append(f"    {key}: {value}")
                if event.details.get("frame"):
                    frame = event.details["frame"]
                    lines.append(
                        "    frame: "
                        f"audio={frame.get('audio_label')} wear={frame.get('wearing')} "
                        f"tlvs={len(frame.get('tlvs') or [])} issues={len(frame.get('issues') or [])}"
                    )
            if event.related:
                related = ", ".join(
                    f"#{other} {events[other].kind} {events[other].timestamp:%H:%M:%S}"
                    for other in event.related[:12]
                )
                suffix = " ..." if len(event.related) > 12 else ""
                lines.append(f"    related: {related}{suffix}")
    lines.append("")
    lines.extend(summary)
    return "\n".join(lines)


def render_html(
    events: list[Event],
    summary: list[str],
    *,
    title: str,
    verbose: bool,
) -> str:
    def esc(value: Any) -> str:
        return html.escape("" if value is None else str(value))

    rows: list[str] = []
    for index, event in enumerate(events):
        timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if event.timestamp else "?"
        if event.details.get("synthetic_time"):
            timestamp = "~" + timestamp
        details = json.dumps(event.details, indent=2, ensure_ascii=False, default=str)
        related_html = ""
        if event.related:
            items = "".join(
                f"<li>#{other} {esc(events[other].kind)} "
                f"{esc(events[other].timestamp.strftime('%H:%M:%S.%f')[:-3])} "
                f"{esc(events[other].summary)}</li>"
                for other in event.related
            )
            related_html = f"<div class='related'><strong>Related</strong><ul>{items}</ul></div>"
        frame_html = ""
        if verbose and event.details.get("frame"):
            frame_html = f"<pre>{esc(json.dumps(event.details['frame'], indent=2, ensure_ascii=False))}</pre>"
        rows.append(
            f"<tr class='kind-{esc(event.kind)}' id='event-{index}'>"
            f"<td class='ts'>{esc(timestamp)}</td>"
            f"<td>{esc(event.source)}</td>"
            f"<td><span class='badge'>{esc(event.kind)}</span></td>"
            f"<td><div>{esc(event.summary)}</div>"
            f"<details><summary>details</summary><pre>{esc(details)}</pre>{frame_html}</details>"
            f"{related_html}</td></tr>"
        )

    summary_html = "".join(f"<li>{esc(line.strip())}</li>" for line in summary[1:])
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 14px/1.45 system-ui, sans-serif; margin: 1.5rem; max-width: 1400px; }}
  h1 {{ font-size: 1.4rem; margin-bottom: .25rem; }}
  .meta {{ color: #666; margin-top: 0; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border-bottom: 1px solid #d0d0d0; padding: .4rem .5rem; vertical-align: top; text-align: left; }}
  th {{ position: sticky; top: 0; background: Canvas; z-index: 1; }}
  tr:nth-child(even) {{ background: rgba(127,127,127,.06); }}
  .ts {{ white-space: nowrap; font-variant-numeric: tabular-nums; }}
  .badge {{ display: inline-block; padding: .05rem .4rem; border-radius: .25rem; font-size: .8rem; background: #e4e4e4; color: #222; }}
  .kind-ble_adv .badge {{ background: #d9ecff; color: #0b3d6b; }}
  .kind-spp .badge {{ background: #ffe3d1; color: #6b2d0b; }}
  .kind-a2dp .badge {{ background: #dff5dd; color: #1d5a1a; }}
  .kind-sdp .badge {{ background: #f0e2ff; color: #4b1a6b; }}
  .kind-l2cap .badge {{ background: #fff4c2; color: #5c4a00; }}
  .kind-connection .badge {{ background: #e6e6e6; color: #333; }}
  details summary {{ cursor: pointer; color: #555; margin-top: .25rem; }}
  pre {{ white-space: pre-wrap; word-break: break-word; background: rgba(127,127,127,.1); padding: .5rem; border-radius: .25rem; }}
  .related {{ margin-top: .4rem; font-size: .9rem; }}
  .related ul {{ margin: .2rem 0 0 1.2rem; padding: 0; }}
  ul.summary {{ columns: 2; }}
</style>
</head>
<body>
<h1>{esc(title)}</h1>
<p class="meta">{len(events)} event(s)</p>
<ul class="summary">{summary_html}</ul>
<table>
<thead><tr><th>Timestamp</th><th>Source</th><th>Kind</th><th>Event</th></tr></thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Correlate Samsung Auto Switch events from btsnoop and btmon captures.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("btsnoop", type=Path, help="Android btsnoop_hci.log")
    parser.add_argument("btmon", nargs="?", type=Path, help="optional btmon text output")
    parser.add_argument("-o", "--output", type=Path, help="write timeline to this file (.html for HTML)")
    parser.add_argument("--window", type=float, default=2.0, help="correlation window in seconds")
    parser.add_argument(
        "--dedupe",
        type=float,
        default=1.0,
        help="collapse identical BLE advertisements within this many seconds",
    )
    parser.add_argument(
        "--keep-duplicates",
        action="store_true",
        help="keep every repeated BLE advertisement",
    )
    parser.add_argument("--verbose", action="store_true", help="include event details")
    parser.add_argument("--debug", action="store_true", help="verbose logging")
    parser.add_argument("--log-json", action="store_true", help="write log lines as JSON")
    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.window < 0:
        parser.error("--window must be zero or greater")
    if args.dedupe < 0:
        parser.error("--dedupe must be zero or greater")


def run(args: argparse.Namespace) -> int:
    if not args.btsnoop.exists():
        LOG.error("btsnoop file not found: %s", args.btsnoop)
        return 2
    if args.btmon is not None and not args.btmon.exists():
        LOG.error("btmon file not found: %s", args.btmon)
        return 2

    timeline = Timeline()
    stats: dict[str, ParseStats] = {}
    failed = False

    try:
        stats["btsnoop"] = parse_btsnoop(args.btsnoop, timeline)
    except ValueError as exc:
        LOG.error("btsnoop: %s", exc)
        failed = True

    if args.btmon is not None:
        try:
            stats["btmon"] = parse_btmon(args.btmon, timeline)
        except ValueError as exc:
            LOG.error("btmon: %s", exc)
            failed = True

    if failed and not stats:
        return 1

    synthetic = assign_missing_timestamps(timeline.events)
    timeline.events.sort(key=lambda event: (event.timestamp, event.order))

    filtered, dropped_spp = filter_spp_events(timeline.events, timeline.spp_channels)
    timeline.events = filtered

    suppressed = 0
    if not args.keep_duplicates:
        timeline.events, suppressed = dedupe_advertisements(timeline.events, args.dedupe)

    cross_source = correlate(timeline.events, args.window)
    summary = summary_lines(
        timeline.events,
        stats,
        timeline,
        cross_source,
        suppressed,
        dropped_spp,
        args.window,
        synthetic,
    )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        if args.output.suffix.lower() in (".html", ".htm"):
            content = render_html(
                timeline.events,
                summary,
                title=f"Auto Switch timeline: {args.btsnoop.name}",
                verbose=args.verbose,
            )
        else:
            content = render_text(timeline.events, summary, verbose=args.verbose)
        try:
            args.output.write_text(content, encoding="utf-8")
        except OSError as exc:
            LOG.error("cannot write %s: %s", args.output, exc)
            return 1
        print(f"Wrote {args.output} ({len(timeline.events)} events)")
        print("\n".join(summary))
    else:
        print(render_text(timeline.events, summary, verbose=args.verbose))

    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)
    configure_logging(args.debug, args.log_json)
    install_excepthook()
    try:
        return run(args)
    except KeyboardInterrupt:
        LOG.info("interrupted")
        return 130
    except Exception:
        LOG.exception("dissection failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
