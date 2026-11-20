# Samsung Galaxy Buds Auto Switch Protocol Specification

Wire-level description of the Samsung Continuity protocol as observed between
a One UI phone, Galaxy Buds, and a Linux peer. Field offsets, magic values,
byte order, and cryptographic parameters are stated explicitly so an
independent implementation can interoperate.

| Field | Value |
|---|---|
| Document status | Living document; live-verified on Linux with physical hardware |
| Date | 2026-11-11 |
| Transport | BLE advertising, RFCOMM SPP, optional L2CAP CoC |

## Confidence markers

| Marker | Meaning |
|---|---|
| `[VERIFIED]` | Confirmed by wire capture or repeatable live behavior |
| `[INFERRED]` | Derived from observed behavior, not directly asserted |
| `[NEEDS VALIDATION]` | Requires a live capture or an unresolved parser detail |

Offsets in the BLE sections index the manufacturer-specific data value for
company ID `0x0075`: the first byte after the 2-byte company ID is offset 0.
Where early findings and later observations disagree on an index, both are
shown and the conflict is tagged.

---

## 1. Transport summary

| Channel | Purpose | Identifier | Evidence |
|---|---|---|---|
| BLE advertising | Device presence, audio state, account identity, auto switch capability | Company ID `0x0075` (117) | observed |
| RFCOMM SPP | Buds opcodes (`SET_SEAMLESS_CONNECTION` and its acknowledgement), resource sharing, copy/paste | UUID `3A622E58-C035-4A26-928C-5601DDE7C657` | observed |
| L2CAP CoC | Phone-directed auto switch commands (`BUDS_SWITCH` request/response, ready events, get-device-state); Samsung proprietary stream, PSM negotiated | `listenUsingInsecureL2capChannel()` | observed |

The BLE path consumes advertisements from earbuds and peer devices. After the
account handshake, phone-directed auto switch commands travel over the BLE
L2CAP CoC (section 5.5): the BUDS_SWITCH request and response, ready events,
get-device-state, and the channel keepalive. `[VERIFIED live]` Buds opcodes
travel over RFCOMM SPP (sections 3 and 4): SET_SEAMLESS_CONNECTION and its
acknowledgement. `[VERIFIED]`

---

## 2. BLE advertising protocol

### 2.1 AD structure and company ID

```
AD structure (legacy advertising)
+--------+--------+------------------+---------------------------+
| Length | 0xFF   | Company ID (LE)  | Manufacturer data         |
| 1 byte | 1 byte | 0x75 0x00        | variable                  |
+--------+--------+------------------+---------------------------+
```

`0xFF` is the "Manufacturer Specific Data" AD type. Samsung uses company ID
117 (`0x0075`). Android strips the company ID before handing the value to
`getManufacturerSpecificData(117)`, so offset 0 below is the vendor version
byte `0x02`. `[VERIFIED]`

### 2.2 Packet header

| Offset | Field | Size | Value | Notes |
|---|---|---|---|---|
| 0 | Version / vendor type | 1 | `0x02` | Always 2 for Samsung MCF |
| 1 | Service subtype | 1 | `0x18` | 24 decimal |
| 2 | Flags byte | 1 | bitfield | See below |
| 3 | Device type and format flags | 1 | bitfield | Upper nibble device type, lower nibble format/type flags |
| 4..12 | Account / personal LTV | 9 | variable | Account identity data |

```
Offset  0      1      2        3              4 ......... 12
        +------+------+--------+--------------+----------------+
        | 0x02 | 0x18 | flags  | type | flags | account LTV    |
        +------+------+--------+--------------+----------------+
```

Flags byte at offset 2, per original findings:

| Bit | Mask | Meaning |
|---|---|---|
| 7 | `0x80` | Extended advertisement flag; packet length >= 21 |
| 6 | `0x40` | Secondary flag; packet length >= 18 |
| 3..0 | `0x0F` | Sub-type identifier; `1` = short address format |

`[VERIFIED]` for the length thresholds and the short-format match, `[INFERRED]`
for the bit labels. The generic scan filter matches offset 2 low nibble = 1:

```text
manufacturer data filter
  company id : 117 (0x0075)
  pattern    : { 0x02, 0x18, 0x01 }
  mask       : { 0xFF, 0xFF, 0x0F }
```
`[VERIFIED]`

#### Index conflict

The length checks read offset 3, not offset 2:

```text
length rules (offset 3)
  (byte[3] & 0x80) == 0                -> accept any length
  (byte[3] & 0x80) != 0 && len >= 21   -> accept (extended format)
  (byte[3] & 0x40) != 0 && len >= 18   -> accept (secondary block)
```
`[VERIFIED]`

The per-device filter builder writes the format byte at offset 3 as well. Consequence: a parser cannot treat our offset tables as
final until a capture settles whether the vendor counts an AD length byte.
This document presents the logical layout and records both readings.

### 2.3 Length classes

| Minimum length | Flag condition | Interpretation `[INFERRED]` |
|---|---|---|
| 14 | Base | Minimum parseable advertisement |
| 18 | Offset 3 bit 6 set | Secondary / account LTV block present |
| 21 | Offset 3 bit 7 set | Extended format, no inline account LTV |

The parser rejects shorter packets as invalid. `[VERIFIED]`

### 2.4 LTV container format

After the header, data is a sequence of type-length-value records. Each record
starts with one header byte:

```
 bit 7 6 5 4 | 3 2 1 0
 +-----------+---------+
 |  length   |  type   |
 +-----------+---------+
```

- High nibble: payload length in bytes, 1 to 14. Zero is invalid.
- Low nibble: record type.
- The record must fit inside the advertised buffer (`offset + length < buffer length`).
  `[VERIFIED]`

| Type | Payload | Record shape | Meaning |
|---|---|---|---|
| 1 | 10+ bytes | device context | Device context ("Ctx") |
| 2 | 2..14 bytes | event | Event: header, sequence, data |
| 3 | 3..5 bytes | advertisement descriptor | Advertisement descriptor ("AD") |
| 4 | 3..4 bytes | account identity | Account / personal identity |
| 5 | unknown | none | Not handled in the parser switch |
| 6 | 1..15 bytes | client/RC list | Client/RC list `[INFERRED]` |
| 7 | 1 byte | RC sequence | RC sequence |
| 8 | 4 bytes | 32-bit value | 32-bit value, big-endian `[INFERRED]` |

`[VERIFIED]` for the dispatch. Type names for 6 and 8
are inferred from the record shape and its textual form only.

Type 3 serialization uses a computed length:

```text
type 3 header byte = ((extra_length + 3) << 4) | 0x03   // 0x33, 0x43, 0x53
payload: advertisement short (2 bytes, big-endian)
         flags (1 byte)
         optional extra (1..2 bytes)
```
`[VERIFIED]`

### 2.5 Device context (Ctx)

Ctx is a fixed logical structure. The generic parser reads it from a type 1
record with relative offsets `[VERIFIED]`:

| Relative offset | Field | Size | Encoding |
|---|---|---|---|
| +5..+6 | `Coc` | 2 | Big-endian short, device context ID |
| +7 | `DS` | 1 | Device state |
| +8 | `NS` | 1 | Notification/status flags |
| +9 | `F` | 1 | Feature/capability flags |
| +10 | `AP` | 1 | Audio playback info; `4096` (`0x1000`) sentinel when absent |

The daemon's implemented behavior is authoritative, and it decodes the
notification byte on two paths. In the account-bound LTV walk the audio state
derives from the record-local byte at `body_start + 3`
(`daemon/src/ble/mod.rs:219`, `daemon/src/ble/mod.rs:234-242`). In the unbound
fallback path it derives from absolute manufacturer-data offset 9, masked
`0xF8` (`daemon/src/ble/mod.rs:152-160`). `[VERIFIED]`
`[NEEDS VALIDATION]`: capture a short and a long advertisement to reconcile the
fallback anchor at absolute offset 9 with the record-local byte.

#### NS flag bits

```
 bit  7 6 5 4 3 2 1 0
      +-+-+-+-+-+-+-+-+
      |?|?|S|R|?|A|F|?|
      +-+-+-+-+-+-+-+-+
```

| Bit | Mask | Meaning | Evidence |
|---|---|---|---|
| 1 | `0x02` | Feature flag | observed |
| 2 | `0x04` | Audio playback indicator (`AP` field present) | observed |
| 4 | `0x10` | SCPM remote-revision API support | observed |
| 5 | `0x20` | Secondary flag | observed |

`[VERIFIED]` for the corresponding helper predicates.
Bits 0, 3, 6 and 7 are unused by these helpers; semantics unknown.

### 2.6 Buds audio state

In the fallback path, used when the account-bound LTV parse is unavailable,
audio state derives from `NS` at absolute index 9 and is computed only when the
packet is longer than 9 bytes (`daemon/src/ble/mod.rs:152-160`) `[VERIFIED]`:

```text
audio state (manufacturer data offset 9, masked 0xF8)
  len <= 9        -> 2 (disconnected / in case)
  0x08            -> 0 (idle / ambient)
  0x48            -> 1 (active streaming)
  any other value -> 2 (disconnected / in case)
```

| `NS & 0xF8` | State | Label |
|---|---|---|
| `0x08` (8) | 0 | Idle / ambient |
| `0x48` (72) | 1 | Active streaming |
| other | 2 | Disconnected / in case |

The mask ignores NS bits 0 to 2, so the feature, AP and secondary bits do not
affect audio state. When the account-bound LTV record is available, audio state
comes from its record-local notification byte instead (section 2.5).

### 2.7 Wear / case state

```text
wearing = manufacturer_data.len() > 36 && (manufacturer_data[36] & 0x01) == 1
```
`[VERIFIED]`

| Offset 36 bit 0 | Meaning |
|---|---|
| 1 | Wearing / out of case |
| 0 | Not wearing / in case |

`[NEEDS VALIDATION]`: confirm which earbud, or whether this is a combined
wearing/case bit, and how it behaves with one bud removed.

### 2.8 Advertisement construction

Two advertisement formats are built `[VERIFIED]`:

| Offset | Short format data | Short mask | Long format data | Long mask |
|---|---|---|---|---|
| 0 | `0x02` | `0xFF` | `0x02` | `0xFF` |
| 1 | `0x18` | `0xFF` | `0x18` | `0xFF` |
| 2 | `0x00` | `0x00` | `0x00` | `0x00` |
| 3 | `0x01` | `0x0F` | `0x00` | `0x80` |
| 4 | payload | payload mask | `0x00` | `0x00` |
| 5.. | payload | payload mask | payload | payload mask |

```
Short:  02 18 00 01 <payload>
Long:   02 18 00 00 00 <payload>
```

The original findings describe byte 2 as `0x01` for short and `0x00` for long.
The builder writes those values at index 3. Treat both descriptions as
provisional until capture. `[NEEDS VALIDATION]`

#### Directed per-device filter

When scanning for a known device address, the phone builds a 10-byte filter
`[VERIFIED]`:

```
Base data:  42 09 81 02 00 00 00 00 00 08
```

| Mask | Bytes | Meaning |
|---|---|---|
| Non-owner | `FF FF FF FF 00 00 00 00 00 78` | Last byte checks bits 3..6 |
| Owner | `FF FF FF FF 00 00 00 00 00 38` | Last byte checks bits 3..5 |

```
Last byte of base data:  0x08 = 0000 1000
Non-owner mask:          0x78 = 0111 1000
Owner mask:              0x38 = 0011 1000
```

Bit 3 must be set to match; the owner mask ignores bit 6, the non-owner mask
requires bit 6 clear. `[INFERRED]` The semantic label of bit 6 (owner versus
non-owner) comes from the call site selecting the mask; captures should confirm
it. `[NEEDS VALIDATION]`

#### Scan settings

| Setting | Value | Evidence |
|---|---|---|
| Scan mode | `100` (low latency) | observed |
| PHY | `1` (LE 1M) | observed |
| Legacy | `!extended` | observed |
| Report delay / timeout | 3120 in custom builder | observed |

### 2.9 Advertisement descriptor (LTV type 3)

The `AD` record carries device capability flags and battery. Field derivation
`[VERIFIED]`:

```
+--------+--------+--------+---------------------+
| adv hi | adv lo | flags  | battery / ws (0..2) |
+--------+--------+--------+---------------------+
```

| Field | Source | Meaning |
|---|---|---|
| `adv` | 2 bytes big-endian | Advertisement identifier short |
| `hfp` | `flags & 0x03` | HFP profile state |
| `a2dp` | `flags & 0x04` | A2DP active |
| `fg` | `flags & 0x08` | Foreground / in use |
| `bis` | `flags & 0x10` | LE Audio broadcast (BIS) |
| `wear` | `flags & 0x20` | Wearing |
| `spp` | `flags & 0x40` | SPP connectable |
| `battery` | `(b[0] & 0x0F) * 10 + ((b[1] & 0xF0) >> 4)` | Battery percent |
| `ws` | `b[0] & 0x80` | Unresolved; appears in the debug string |

The debug string is `AD{adv=, a2dp=, hfp=, wear=, spp=, ws=, fg=, bis=}`. `[VERIFIED]`

```
Flags byte layout (type 3)
 bit 7 6 5 4 3 2 1 0
      ? S W B F A H H
        | | | | | | +--- HFP state (2 bits)
        | | | | | +----- A2DP
        | | | | +------- Foreground
        | | | +--------- BIS
        | | +----------- Wear
        | +------------- SPP
        +--------------- unused
```

`[INFERRED]` from the mask constants; bit assignments verified individually.

### 2.10 Foreground and multipoint TLVs

A state TLV drives auto switch decisions `[VERIFIED]`
:

| Condition | Field | Meaning |
|---|---|---|
| `b[3] == 11` | `b[4]` | State |
| | `b[5]` | Reason |
| | `b[6]` | Foreground auto switch version |
| | `b[7]` | Foreground major class |
| | `b[8..9]` | Foreground account hash |
| | `b[10]` | Foreground streaming state |
| `b[3] & 0x10` | bit 4 | Multipoint supported |
| `b[3] == 1` | | Subscribed |
| `b[3] < 2` | | SPP connectable, value is connection count |

The byte at index 3 here belongs to a decrypted TLV value, not the
advertisement header. `[NEEDS VALIDATION]` for the exact TLV wrapper and
whether index 3 is always a type byte.

---

## 3. RFCOMM SPP control channel

### 3.1 Service record

```text
SDP service record
  service name : "CONTINUITY_MSG_SPP"
  service UUID : 3A622E58-C035-4A26-928C-5601DDE7C657
  socket       : insecure RFCOMM (no MITM or authenticated pairing required)
```
`[VERIFIED]`

| Property | Value |
|---|---|
| Service name | `CONTINUITY_MSG_SPP` |
| UUID | `3A622E58-C035-4A26-928C-5601DDE7C657` |
| Socket type | Insecure RFCOMM (no MITM/authenticated pairing requirement) |
| Role | Phone listens; earbuds connect |

### 3.2 Command message model

Commands are protobuf messages. The builder produces a command with six
logical fields `[VERIFIED]`:

```text
command envelope
  device_address : string
  handler        : u8
  command        : u8
  type           : u8
  payload        : bytes (optional)
  extra          : u8 (normally 0)
```

| Field | Wire field | Meaning |
|---|---|---|
| address | address | Target Bluetooth address |
| handler | handler | Handler id (1 = Auto Switch) |
| command | command | Command id |
| type | type | Request, response, or event type |
| payload | payload | Opaque command payload |
| extra | extra | Extra integer, normally 0 |

When serialized, the inner message wraps a command id, a type, and a payload;
the outer message carries the handler, a sequence number, the encrypted
payload, and a result field. Exact protobuf field numbers
are not asserted by the observed behavior. `[NEEDS VALIDATION]`

#### Decrypted frame layout

After AES-CBC decryption, the command frame starts with one packed byte
`[VERIFIED]`:

```
 bit 7 6 5 4 | 3 2 1 0
 +-----------+---------+
 |   appId   |  appSeq |
 +-----------+---------+
```

The parser uses offset 2 of the frame for short formats and offset 4 for
account-LTV formats, then walks type-length records from there. `[VERIFIED]`

### 3.3 Auto switch request

```text
BUDS_SWITCH request body
  [0..2)  advertisement short, big-endian
  [2..8)  Bluetooth address, 6 bytes
  [8]     request type (1 = media, 2 = call)
envelope: handler = 1, command = 1, type = 1
```
`[VERIFIED]`

| Field | Size | Value |
|---|---|---|
| Advertisement short | 2 | Big-endian device advertisement ID |
| Bluetooth address | 6 | Target MAC, no separators |
| Request type | 1 | Requester role or action, caller supplied |

| Envelope field | Value |
|---|---|
| handler | 1 |
| command | 1 |
| type | 1 |

Total payload length: 9 bytes. The address encoder accepts 12- or 6-character
strings and returns 6 bytes. `[VERIFIED]`

### 3.4 Ready event

```text
ready event: handler = 1, command = 10, type = 3, empty payload
```
`[VERIFIED]`

| Envelope field | Value |
|---|---|
| handler | 1 |
| command | 10 |
| type | 3 |
| Payload | none |

This event tells the peer the phone is ready to receive or perform a switch.

### 3.5 Handoff command

`HandoffCommand` parses the decrypted payload as:

```
+--------+------------+---------------------------+
| appId  | resultCode | extras (optional)         |
| 1 byte | 1 byte     | remaining bytes           |
+--------+------------+---------------------------+
```

| Field | Offset | Values |
|---|---|---|
| `appId` | 0 | `1` for handoff |
| `resultCode` | 1 | `1` = success; other values are error states |
| Extras | 2..n | Present only when `appId == 1` and `resultCode == 1` |

Rules `[VERIFIED]`:

- Empty payload returns false.
- Request type 1 or 3 skips result parsing.
- Payload shorter than 2 bytes on a response returns false.
- `resultCode == 1` with fewer than 3 bytes returns false ("No extras").
- When the request type is 1, extras are decoded as a UTF-8 string
.
- Other result codes carry no extras in this parser.

`[NEEDS VALIDATION]`: enumerate result codes other than 1 from live traffic.

### 3.6 Related app IDs

| app id | Command family | Purpose |
|---|---|---|
| 1 | handoff | Audio handoff between devices |
| 1 | auto switch | Auto switch request and ready event |
| 9 | Resource sharing request | Cross-device resource |
| 0 | copy/paste | Clipboard sync |

`[VERIFIED]` for the constants; app id 1 is reused across command types,
selected by the type byte.

### 3.7 Copy/paste result codes (sibling protocol)

`CopyPasteCommand` accepts these result codes
`[VERIFIED]`:

| Result code | Extras |
|---|---|
| 1, 4, 7, 8 | Present, bytes 2..n |
| 2, 3, 5, 6, 9 | None |

Included because it shows the shared result-code pattern, not because it
belongs to auto switch.

---

## 4. Galaxy Buds SPP opcodes

### 4.1 Framing

Buds SPP messages carry an opcode and a payload:

```text
buds SPP message
  opcode  : u8      // first byte on the wire
  payload : bytes   // opcode-specific
  flag    : bool
  flag2   : bool
```

The opcode is the first byte on the wire. The payload is opcode-specific.
`[VERIFIED]` for object shape; exact wire framing (length prefix, checksum)
is not visible in these classes. `[NEEDS VALIDATION]`

Application-level messages name a command plus a value for sends and carry
the device address, action, and value for receives. `[VERIFIED]`

### 4.2 Opcode table

| Opcode | Signed | Direction | Name | Payload |
|---|---|---|---|---|
| `0xAF` | -81 | Phone to buds | `SET_SEAMLESS_CONNECTION` | 1 byte: `0x00` disable, `0x01` enable |
| `0x77` | 119 | Reported for auto switch | `AUTO_SWITCH_AUDIO_OUTPUT` | Reported as none; outbound payload unknown |
| `0x73` | 115 | Buds to phone `[INFERRED]` | `AUTO_SWITCH_AUDIO_OUPUT` ack | None |
| `0x1B` | 27 | Phone to buds | `ACTION_MSG_AUTO_SWITCH_LEFT_AND_RIGHT` | 1 byte flag |
| `0x78` | 120 | Phone to buds | `NOISE_CONTROLS_SETUP` | 1 byte mode |
| `0x77` | 119 | Buds to phone | `NOISE_CONTROLS_UPDATE` | 1 byte mode |

`[VERIFIED]` for `0xAF`, `0x1B`, `0x73` and the two `0x77` handlers. The
`AUTO_SWITCH_AUDIO_OUTPUT` opcode is conflicting; see 4.4. Directions for
`0x73` and the auto switch row follow the receive-side handlers and are not
confirmed on the wire.

### 4.3 SET_SEAMLESS_CONNECTION (`0xAF`)

Send path `[VERIFIED]`:

```text
send opcode 0xAF with payload [ enabled ? 0x01 : 0x00 ]
```

| Field | Value |
|---|---|
| Opcode | `0xAF` (-81) |
| Payload | 1 byte boolean |
| `0x00` | Disable seamless connection |
| `0x01` | Enable seamless connection |

Ack path `[VERIFIED]`:

```text
on 0xAF acknowledgement:
  seamless_enabled = next byte == 0x01
  broadcast SEAMLESS_CONNECTION_UPDATED
```

The state is stored in device info field `L` and broadcast as
`ACTION_MSG_ID_SEAMLESS_CONNECTION_UPDATED`.

### 4.4 AUTO_SWITCH_AUDIO_OUTPUT (`0x77` reported, `0x73` observed)

The original findings assign opcode `0x77` (119) to
`AUTO_SWITCH_AUDIO_OUTPUT` with no payload. The acknowledgement
handlers disagree across observed builds:

| Handler | Value | Label |
|---|---|---|
| observed build A | `119` (`0x77`) | `NOISE_CONTROLS_UPDATE` |
| observed | `115` (`0x73`) | `AUTO_SWITCH_AUDIO_OUPUT` |
| observed | `115` (`0x73`) | `AUTO_SWITCH_AUDIO_OUPUT` |
| observed | `115` (`0x73`) | `AUTO_SWITCH_AUDIO_OUPUT` |
| observed | `115` (`0x73`) | `AUTO_SWITCH_AUDIO_OUPUT` |

`[VERIFIED]` for all five call sites. No send path for either value was observed, so the true outbound opcode is not
established. Two possibilities:

1. `0x77` is the outbound command and `0x73` is the acknowledgement.
2. The findings describe a different Buds firmware generation.

`[NEEDS VALIDATION]`: capture a switch with `btsnoop_hci.log` or an SPP proxy
and record the outbound opcode and its acknowledgement.

### 4.5 Related auto switch opcode (`0x1B`)

```text
on ACTION_MSG_AUTO_SWITCH_LEFT_AND_RIGHT:
  send opcode 0x1B (27) with payload [ left_right ? 0x01 : 0x00 ]
```
`[VERIFIED]`

`SamsungMFFormat.SSdevice.CAMCORDER` is `27` (`0x1B`).
One-byte payload, likely a left/right audio routing toggle.
`[NEEDS VALIDATION]` for the payload semantics.

### 4.6 Acknowledgement handling

Acknowledgements arrive as `MsgUniversalAcknowledgement` with the same opcode
byte as the command. The handler switches on `byteBufferWrap.get()` and then
reads any state bytes. Observed patterns `[VERIFIED]`:

| Opcode | Label | State read | Broadcast |
|---|---|---|---|
| `0xAF` | `SET_SEAMLESS_CONNECTION` | 1 boolean | `ACTION_MSG_ID_SEAMLESS_CONNECTION_UPDATED` |
| `0x73` | `AUTO_SWITCH_AUDIO_OUPUT` | none | none |
| `0x78` | `NOISE_CONTROLS_SETUP` | 1 byte | `NOISE_CONTROLS_UPDATE` |

`[NEEDS VALIDATION]`: full opcode map for the Buds generation under test.

---

## 5. Cryptography and identity

| Algorithm | Mode / size | Use | Evidence |
|---|---|---|---|
| AES | GCM, 128-bit tag, 12-byte IV | Local secure database values | observed |
| AES | CBC, PKCS5 padding, 16-byte IV prepended | SPP command encryption | observed |
| SHA-256 | Digest | Token and identity hashing | observed |
| ECDH | P-256 | Session key agreement | observed |
| X.509 | Certificate parsing | Samsung root cert selection | observed |

### 5.1 SPP payload encryption

```text
SPP command encryption (AES-CBC, PKCS#5/#7 padding)
  key  : 16 or 32 bytes (ECDH session secret)
  iv   : 16 random bytes per message
  wire : IV || ciphertext

decryption
  iv    : input[0..16)
  plain : AES-CBC-decrypt(key, iv, input[16..])
```
`[VERIFIED]`

| Property | Value |
|---|---|
| Key size | 16 or 32 bytes, from ECDH secret or stored key |
| IV | Random, prepended in clear |
| Integrity | None inside `ca/e`; depends on protobuf validation |

Security observation: AES-CBC without a MAC means a captured frame can be
modified or replayed. The receiver relies on protobuf parsing and result codes,
not cryptographic authentication. Note this as a design risk when implementing
interoperability.

### 5.2 Session key agreement

```text
session key = ECDH(P-256, local_private, peer_public)   // 32 bytes
The raw shared secret is used directly as the AES key; no additional KDF is applied.
```
`[VERIFIED]`

No HKDF or KDF call is visible between `generateSecret()` and
`SecretKeySpec(..., "AES")`. The 32-byte P-256 secret is used directly as an
AES-256 key. `[INFERRED]` Confirm with a capture of the key schedule if
implementing the phone side. `[NEEDS VALIDATION]`

### 5.3 Local secure database

- 16-byte AES key generated with `SecureRandom` on first use
.
- Key encrypted and persisted through `h.c()`; failure counter stored in
  `db_key_pref`.
- Values encrypted as `Base64(IV[12] || GCM ciphertext || tag)`.
- GCM tag length 128 bits.

`[VERIFIED]`

### 5.4 Account identity in advertisements

Bytes 4..12 of the advertisement carry "personal account LTV" data. The
account record is LTV type 4: a 6-bit identity value plus a 2-byte account
number (3 bytes when the subtype is 5). Serialization
writes `0x34` (length 3, type 4), a sequence byte, and a 2-byte account
identifier. `[VERIFIED]`

Samsung Account tokens identify the device owner in advertisements and in
auto switch requests. The app does not decode the token contents; it treats
them as opaque identifiers. `[NEEDS VALIDATION]` for token generation and
rotation.

### 5.5 Command channel over the BLE CoC

After the account handshake the same transport carries commands. The outer
envelope is a protobuf message: field 1 handler, field 2 sequence, field 3
encrypted payload, field 4 advertising payload, field 5 revision, field 6
authentication type, field 7 IV. The decrypted payload is a second protobuf
message: field 1 command id, field 2 type, field 3 payload. Encryption is
AES-256-CBC with a random 16-byte IV prepended, under the raw ECDH session
key. `[VERIFIED live]`

The phone routes received commands by handler id. Handler 1 is the Auto Switch
handler:

| Message | H | C | T | Body |
|---|---|---|---|---|
| BUDS_SWITCH request | 1 | 1 | 1 | `[advId:2 BE][address:6][reason:1]` |
| BUDS_SWITCH response | 1 | 1 | 2 | `[result:1][advId:2][address:6]` |
| Ready event | 1 | 10 | 3 | empty |
| Stub event | 1 | 11 | 3 | empty |
| Get device state | 1 | 5 | 1 | empty (reply T=2: `[state:1]`) |
| Channel keep | 100 | 3 | 1 | `[keep:1]` (reply T=2 empty) |

`advId = ((XOR of the six address bytes) & 0xFF) << 8 | address[5]`
(big-endian on the wire, validated on device). Reason 1 means media playback,
2 means a phone call. The phone mutes its media, switches the Buds itself, and
replies; the PC honors incoming requests by pausing MPRIS, disconnecting
A2DP/HFP, and answering result 1.

A BLE command channel is closed by the phone after a short idle window
("Connection timeout"); any received non-control command resets that timer.
A get-device-state request every 15 s keeps the channel open. `[VERIFIED live]`

---

## 6. Local persistence

Room database migration 1 to 2 creates the auto switch table
`[VERIFIED]`:

```sql
CREATE TABLE IF NOT EXISTS `mcfds_auto_switch_table` (
    `column_id`    INTEGER NOT NULL,
    `column_value` INTEGER NOT NULL,
    PRIMARY KEY(`column_id`)
);
```

| Column | Type | Constraints |
|---|---|---|
| `column_id` | INTEGER | NOT NULL, primary key |
| `column_value` | INTEGER | NOT NULL |

Entity: the auto switch preferences table. The row semantics (which IDs map to which auto switch
settings) are not in the schema. `[NEEDS VALIDATION]`

Identity hash for this schema version: `a1f2f25f7effa61257653cb67d8be06c`. Included for database compatibility checks.

---

## 7. Samsung multi-connectivity ecosystem

The global scanner registers filters for other vendors
`[VERIFIED]`:

| Name | Company ID | Data | Mask | Notes |
|---|---|---|---|---|
| `SAMSUNG_MCF` | 117 | `{0x02, 0x18, 0x01}` | `{0xFF, 0xFF, 0x0F}` | Samsung MCF, short format |
| `APPLE_NEARBY` | 76 | `{0x10}` | `{0xFF}` | Apple Nearby Info |
| `APPLE_HAND_OFF` | 76 | `{0x0C}` | `{0xFF}` | Apple Handoff |
| `APPLE_NEARBY_ACTION` | 76 | `{0x0F}` | `{0xFF}` | Apple Nearby Action |
| `XIAOMI` | 911 | `{0x00}` | `{0x00}` | Matches any Xiaomi data |
| `VIVO` | 2103 | `{0x00}` | `{0x00}` | Matches any Vivo data |
| `OPPO` | 1946 | `{0x00}` | `{0x00}` | Matches any Oppo data |
| `HONOR_1` | n/a | service data | `{0x00}` | Service UUID `0000fcf7-0000-1000-8000-00805f9b34fb` |
| `HONOR_2` | n/a | service data | `{0x00}` | Service UUID `0000fcf8-0000-1000-8000-00805f9b34fb` |

Mask `{0x00}` for Xiaomi, Vivo and Oppo means the filter matches on company ID
alone. Any advertisement from those vendors enters the scan callback.

```
Company ID 117 = 0x0075
```

The shared ecosystem scanner demonstrates that Samsung MCF coexists with
Apple Continuity, Xiaomi, Vivo, Oppo and Honor proximity advertisements on the
same BLE scan.

---

## 8. End-to-end auto switch sequence (inferred)

```
Phone A                      Buds                      Phone B
  |                            |                          |
  | BLE adv: 02 18 .. audio=1  |                          |
  |--------------------------->|                          |
  |                            |  BLE adv to Phone B      |
  |                            |------------------------->|
  |                            |                          |
  | SPP connect (UUID ..C657)  |                          |
  |<==========================>|<========================>|
  | CoC connect (L2CAP)        |                          |
  |<=====================================================>|
  | makeReadyEvent (appSeq 10) |                          |
  |------------------------------------------------------>|
  | makeAutoSwitchRequest      |                          |
  | (appSeq 1, type 1)         |                          |
  |------------------------------------------------------>|
  | HandoffCommand result=1    |                          |
  |<------------------------------------------------------|
  | SET_SEAMLESS_CONNECTION    |                          |
  | 0xAF 01                    |                          |
  |--------------------------->|                          |
  | Acknowledgement 0xAF       |                          |
  |<---------------------------|                          |
```

Steps and envelope values are verified individually. Their ordering is
inferred from command semantics and is not guaranteed by the code.
`[NEEDS VALIDATION]`

---

## 9. Validation plan

Capture these before implementing a compatible client.

| # | Capture | Confirms |
|---|---|---|
| 1 | Short advertisement, hex dump | Header offsets 2/3, bit 7/6 semantics, LTV base offset |
| 2 | Long advertisement, hex dump | Extended format, `0x80`/`0x40` bits, length thresholds |
| 3 | Buds idle, streaming, in case | Audio state mapping in section 2.6 |
| 4 | One bud removed, both removed | Wear bit at offset 36 |
| 5 | Two phones, same account | Account LTV type 4 contents and rotation |
| 6 | SPP open and idle | Handshake, protobuf field numbers, framing |
| 7 | Auto switch trigger | Outbound opcode `0x77` versus `0x73`, ack opcode |
| 8 | Seamless toggle on/off | `0xAF` payload and `L` state update |
| 9 | Left/right routing change | `0x1B` payload meaning |
| 10 | Directed scan for known device | Owner versus non-owner mask bit 6 |
| 11 | ECDH handshake | Key derivation, IV, any KDF |
| 12 | Noise controls change | Whether `0x77` collides with auto switch |

For each capture record: phone model, Buds model, firmware version, Android
version, app version, and the raw hex or `btsnoop_hci.log` segment.

---

## 10. Evidence standard

Every claim carries one marker:

| Marker | Requirement |
|---|---|
| `[VERIFIED]` | Reproduced on Linux against physical Samsung hardware, or repeated across at least two captures |
| `[INFERRED]` | Consistent with observed behavior but not directly asserted |
| `[NEEDS VALIDATION]` | Needs a dedicated capture before an implementation may depend on it |

## 11. Open questions

| # | Question | Impact |
|---|---|---|
| 1 | Does offset 2 or offset 3 hold the format byte in Android's manufacturer data? | Parser entry point |
| 2 | Is `0x77` the auto switch command, the noise control update, or both per firmware? | Command dispatch |
| 3 | What are the upper 4 bits of the advertisement offset 3 byte? | Device type table |
| 4 | Which KDF, if any, follows ECDH? | Interop with phone |
| 5 | What does `ws` in the AD record mean? | State reporting |
| 6 | What are `column_id` keys in the auto switch table? | Persistence compatibility |
| 7 | Does the account LTV update on token refresh, and how often? | Identity tracking |
| 8 | Is the `0xAF` payload acknowledged with the same byte or a state echo? | Seamless toggle |
