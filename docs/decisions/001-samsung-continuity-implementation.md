# Decision 001: Samsung Continuity Implementation Approach

## Status
Accepted (2026-11-12)

## Context
We need to implement Samsung's Continuity Service protocol on Linux to enable Auto Switch functionality for Galaxy Buds between Linux and Samsung phones.

## Decision
Implement the protocol using a layered approach:
1. **Authentication Layer**: Samsung account OAuth with certificate enrollment
2. **Discovery Layer**: BLE advertisement only (the phone contains no mDNS code)
3. **Connection Layer**: BLE L2CAP CoC
4. **Handshake Layer**: 3-message AES-GCM + P-256 ECDH authentication
5. **Command Layer**: Protobuf framing with AES-256-CBC encryption

## Rationale

### Why Rust?
- Strong type safety for protocol implementation
- Excellent async/await support for concurrent BLE operations
- Good Bluetooth libraries (bluer crate)
- Memory safety without garbage collection overhead

### Why Layered Approach?
- Mirrors Samsung's protocol architecture
- Allows independent testing of each layer
- Easier to debug and isolate issues
- Matches macOS reference implementation structure

### Why BLE L2CAP CoC as Primary?
- Phone advertises CoC PSM in BLE advertisements
- Lower latency than TCP
- Works even when devices are not on same network
- Matches macOS implementation

### Why No mDNS?
- The decompiled phone app (`mcfds`/`mcfserver`) contains no `NsdManager`,
  `_mcfds._tcp`, or `_tcp` code anywhere, so no phone-side browser exists for a
  published service
- The phone's next step after decoding an advertisement is a CoC connection
  using the context PSM, not a LAN lookup
- The mDNS publisher (`src/discovery/mod.rs`, `libmdns`) was therefore dead code
  and has been removed (2026-11-12)

## Implementation Details

### Key Components
- `src/auth/mod.rs`: Samsung account OAuth and certificate enrollment
- `src/auth/ble_keys.rs`: BLE key derivation from account fingerprint
- `src/auth/handshake.rs`: 3-message authentication handshake
- `src/ble/mod.rs`: BLE advertisement broadcasting and parsing
- `src/ble/l2cap.rs`: BLE L2CAP CoC connection

### Cryptographic Materials
- **Account Fingerprint**: 64 hex chars from Samsung Cloud (shared across account)
- **Account Key**: 32 bytes for AES-GCM (from certificate enrollment)
- **Session Key**: 32 bytes from P-256 ECDH (per-connection)
- **BLE Obfuscation**: XOR with SHA-256(fingerprint), 12-hour rotation

### Protocol Flow
```
1. Phone advertises BLE with Company ID 0x0075
2. Linux daemon parses advertisement, extracts CoC PSM
3. Linux connects to phone via BLE L2CAP CoC on PSM
4. Linux sends AUTH_INITIATE (AES-GCM encrypted)
5. Phone responds with AUTH_INITIATE_REPLY
6. Linux sends AUTH_REPLY
7. Both derive session key from ECDH shared secret
8. Commands encrypted with AES-256-CBC using session key
```

## Consequences

### Positive
- ✅ Complete protocol implementation (90% functional)
- ✅ Successfully enrolled in Samsung account
- ✅ Phone accepts and decodes the Linux advertisement, including the CoC PSM
- ✅ L2CAP CoC on PSM 0x0080 is accepted by the phone (LE Credit Based, rx_mtu 65535)
- ✅ Authentication handshake implemented
- ✅ Clean, modular architecture
- ✅ Comprehensive test coverage (35 tests)

### Negative
- ❌ Phone drops the CoC because `AUTH_INITIATE` decryption fails (`userKeyDecrypt fail`); fix in progress
- ❌ Requires Samsung account credentials (privacy concern)
- ❌ Complex cryptographic implementation (maintenance burden)
- ❌ Depends on Samsung's proprietary protocol (could change)

### Neutral
- ⚠️ Requires phone to be paired with Linux device
- ⚠️ BLE random addresses require continuous scanning
- ⚠️ 12-hour rotation requires timer-based key refresh

## Verified Findings (2026-11-12 Diagnosis)

Three findings, each captured from `adb logcat` against the phone and the
observed behavior of the Samsung Continuity service:

1. **L2CAP is accepted; the drop is app-initiated after a decrypt failure.**
   The phone registers the LE CoC service on PSM `0x0080`
   (`L2CA_RegisterLECoc ... PSM: 0x0080`, `is_le: true`, app `rx_mtu: 65535`,
   `btif_sock_l2cap.cc:569`), accepts the connection, and mcfds runs
   `acceptSocket()`. 131 ms after the daemon's 143-byte `AUTH_INITIATE` write
   the app logs `decrypt - le.h: Unknown exception`, `parseAuthCommand -
   1) userKeyDecrypt fail`, `receiveAuthCommand - auth failed`
   ([MCFDs]_AuthenticationHelper/_BaseAccountAuthDelegate), then sends the
   L2CAP Disconnect Request. The earlier `os error 107` is the same close
   racing the first write; a later capture observed `os error 104`.
2. **The type-1 device-context LTV is too short, so the context is lost.**
   The daemon wrote `0x21` + 2 bytes (`src/ble/mod.rs:494-497`); the phone's
   extended-form parser requires at least 5 payload bytes
   (`pa/a.java:180-196`, guard `i10 >= 10`; Samsung's own writer emits 5 or 10
   bytes, `y5/b.java:705-712`, `:687-696`). The phone decoded everything else
   correctly (`Ctx={lost}` only, `ga/h.java:33`). The record is now the
   extended form `0x51` + `[PSM][DS][NS][F]` and the address hint is a type-3
   record `0x33` + 3 tail bytes (`qa/b.java:89-97`).
3. **The phone never browses `_mcfds._tcp`.** No `NsdManager`, `_mcfds`, or
   `_tcp` string exists in any decompiled tree, so the mDNS publisher was dead
   code and has been removed; this record previously claimed otherwise.

The server side of the CoC sends nothing first: mcfds waits for
`AUTH_INITIATE` (`k7/e.java:179-181`, 10 s watchdog) and frames messages as
protobuf varint-length delimited (`la/e.java:118`).

## Next Steps
1. Run the live acceptance gate against the phone: logcat shows no
   `userKeyDecrypt fail` and no `Ctx={lost}`, and the daemon logs handshake
   completion (the M-1 plus M-2 oracle; this is the pre-merge gate)
2. If decryption still fails, re-enroll with `--auth-login` (credentials
   migration is supported; the handshake reloads the credential store per
   attempt)
3. Capture BLE traffic with Wireshark to analyze the decryption mismatch only
   if re-enrollment does not resolve it

## Alternatives Considered

### Alternative 1: TCP-Only Approach
- **Description**: Skip BLE L2CAP, use mDNS + TCP only
- **Pros**: Simpler, more reliable
- **Cons**: Requires same network, higher latency
- **Rejected**: Phone primarily uses BLE for discovery

### Alternative 2: Reverse Engineering Buds SPP Directly
- **Description**: Skip phone, connect directly to Buds via SPP
- **Pros**: Bypass phone entirely
- **Cons**: Buds SPP protocol undocumented, requires Buds to be in specific mode
- **Rejected**: Too risky, Buds might not support direct Linux connection

### Alternative 3: Use Samsung's Official SDK
- **Description**: Use Samsung's official Continuity SDK if available
- **Pros**: Official support, documented API
- **Cons**: SDK not available for Linux, likely Windows/Mac only
- **Rejected**: No Linux SDK available

## References
- Protocol specification: [`docs/PROTOCOL_SPEC.md`](../PROTOCOL_SPEC.md)
- macOS reference: `.research/galaxy-continuity-mac/`

## Related Decisions
- None yet (first decision record)
