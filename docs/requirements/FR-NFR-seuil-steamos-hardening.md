# Seuil SteamOS Hardening Sprint: Functional and Non-Functional Requirements

**Version:** 1.0
**Date:** 2026-11-18
**Author:** [Author]
**Status:** DRAFT

---

### 1. Introduction

**Purpose:** This document specifies the system behaviors and quality attributes the hardening sprint must deliver, with acceptance criteria the test step can execute without interpretation.

**Relationship to URD:** This document derives from URD-seuil-steamos-hardening.md. Every functional requirement traces to at least one user requirement.

**Relationship to BRD:** Non-functional requirements may trace directly to business requirements when they originate from policy (credential secrecy, SteamOS survival).

**Binding language:** `SHALL`/`MUST` = mandatory, `SHOULD` = recommended, `MAY` = optional (RFC 2119). The keyword appears in uppercase inside every FR and NFR statement.

**Evidence base:** the four read-only audits (transport, audio, auth and setup, SteamOS) and the settled decisions recorded in `DECISIONS.md` at the repository root and `docs/decisions/`; findings cited per requirement carry file:line.

### 2. Functional requirements

| ID | Requirement | Traces to | Priority | Acceptance criteria |
|----|-------------|-----------|----------|---------------------|
| FR-001 | `seuil doctor` SHALL run every check, print one line per check, exit 0 when all pass, 1 when any blocking check fails, and 2 on an internal error. | UR-002, UR-007 | Must | See 2.1 |
| FR-002 | The installer SHALL provide a prebuilt path (`install.sh --from-release`) that downloads the release artifact into `~/.local/bin` without invoking any compiler or package manager. | UR-001 | Must | See 2.2 |
| FR-003 | The user service SHALL stay started across a Gaming Mode to Desktop Mode session change and SHALL start on a pure Gaming Mode boot, waiting for Bluetooth readiness instead of exiting when BlueZ is not yet up. | UR-001 | Must | See 2.3 |
| FR-004 | Missing optional runtime tools SHALL degrade only the matching feature with a clear persistent warning, and a failing tool invocation SHALL be distinguished from a missing service record. | UR-002, UR-005 | Must | See 2.4 |
| FR-005 | Setup SHALL print the optional BlueZ experimental drop-in content and the exact privileged command that installs it, SHALL write `/etc` only behind an explicit flag, and SHALL include the SteamOS `/etc` allowlist caveat in the printed text. | UR-001, UR-002 | Should | See 2.5 |
| FR-006 | The release pipeline SHALL produce an x86_64-unknown-linux-gnu artifact built on a Debian 11 (glibc 2.31) baseline with rustls so no OpenSSL links, verified to run on glibc 2.31 or newer. | UR-001 | Must | See 2.6 |
| FR-007 | The README SHALL document the Steam Deck install path and the sprint SHALL record the SteamOS install architecture in a numbered decision record under `docs/decisions/`. | UR-001, UR-002 | Must | See 2.7 |
| FR-008 | The manufacturer-data parser SHALL accept payloads whose format byte validates at either offset 2 or offset 3, SHALL reject only when both readings fail, and SHALL survive truncated or malformed records without panicking and without discarding valid records elsewhere in the buffer. | UR-005 | Must | See 2.8 |
| FR-009 | On suspend (logind PrepareForSleep true) and on adapter power-off, the daemon SHALL tear down CoC channels and stop scanning and advertising; on wake or power-on it SHALL re-initialize each session exactly once, with no duplicate advertisements, leaked tasks, or stale channel entries. | UR-005 | Must | See 2.9 |
| FR-010 | The daemon SHALL enforce a 10 s minimum dwell between handoff requests and an exponential CoC connect backoff starting at 1 s and capped at 60 s, both configurable in config.toml with those defaults. | UR-003 | Must | See 2.10 |
| FR-011 | The daemon SHALL pair and dial only advertisements from the configured phone address and SHALL verify inbound advertisement checksums against the account fingerprint before acting on them. | UR-005 | Must | See 2.11 |
| FR-012 | Background event loops SHALL handle address-parse and crypto-size failures as errors, bound keepalive and frame reads with timeouts configurable in config.toml (default 10 s each), and cap per-peer bookkeeping maps at a configurable limit (config.toml, default 256 entries). | UR-005 | Must | See 2.12 |
| FR-013 | The daemon SHALL route auto switch traffic per the settled transport split: phone-directed commands over the BLE L2CAP CoC and Buds opcodes (SET_SEAMLESS_CONNECTION and its acknowledgement) over RFCOMM SPP, with the Buds SPP frame parser rejecting short or malformed frames without panicking. | UR-003, UR-005 | Must | See 2.13 |
| FR-014 | The daemon SHALL prevent concurrency faults with observable outcomes: a closed channel leaves no entry that blocks future dials to that peer, one peer's blocked channel does not stall other peers, and a hung connect attempt does not accumulate duplicates. | UR-005 | Must | See 2.14 |
| FR-015 | Discovery restarts SHALL stop the previous session before reapplying filters, a rejected discovery filter SHALL produce a visible warning, and the advertiser SHALL retry registration failures with backoff instead of exiting. | UR-005 | Must | See 2.15 |
| FR-016 | The media monitor SHALL treat a stream as active only while it is RUNNING and its peak stays above -60 dBFS across a 200 ms window, SHALL exclude capture-side and communication-class streams, and SHALL expose the threshold and window as config.toml keys with those defaults. | UR-004 | Must | See 2.16 |
| FR-017 | An active HFP call SHALL block media-reason handoffs, call-reason switching SHALL remain allowed during HFP, and the call guard SHALL be scoped to call-reason responses rather than cleared by any response. | UR-004, UR-003 | Must | See 2.17 |
| FR-018 | Probe or service failures SHALL NOT fabricate activity edges: a failed probe SHALL hold the last known state rather than emitting a stop followed by a start, probes SHALL be timeout-bounded, and the monitor task SHALL be supervised so its death is visible and recoverable. | UR-004, UR-005 | Must | See 2.18 |
| FR-019 | On a release request the daemon SHALL verify the pause succeeded and complete profile teardown before answering the phone, and on a granted switch it SHALL retry the A2DP connect; a call-reason response SHALL NOT trigger an A2DP pull. | UR-003, UR-004 | Must | See 2.19 |
| FR-020 | A missing, unreadable, or wrong-length credentials.key SHALL fail credential loading with a specific error and no silent regeneration, and credential writes SHALL be atomic, durable across a crash, and resilient to stale temp files. | UR-006, UR-005 | Must | See 2.20 |
| FR-021 | The daemon and setup SHALL NOT print account keys or tokens to stdout or logs, and debug formatting of credential structures SHALL redact secret fields. | UR-006 | Must | See 2.21 |
| FR-022 | config.toml and the systemd unit SHALL be written atomically, the config directory SHALL carry owner-only permissions, and an invalid config.toml SHALL abort startup with the parse error instead of silently using defaults. | UR-005, UR-006 | Must | See 2.22 |
| FR-023 | The daemon SHALL refresh expiring tokens at runtime, re-enroll when the handshake indicates invalid credentials with bounded retries and a user-visible escalation, re-acquire its Bluetooth session after a bluetoothd restart, and back off pairing failures. | UR-005, UR-006 | Must | See 2.23 |
| FR-024 | The test suite SHALL cover malformed LTV and L2CAP frames under both format-byte readings, the audio-state anchor on short and long advertisements, the dwell and backoff boundaries, sleep/wake state resets, the active-audio filter rule, and the doctor exit contract, and every existing test SHALL keep passing. | UR-007 | Must | See 2.24 |
| FR-025 | The sprint SHALL be verified by cargo check, cargo clippy with warnings denied, cargo test, and a release build, all passing; the live phone gate is reported pending as a separate pre-merge criterion. | UR-007 | Must | See 2.25 |

#### 2.1 FR-001: Doctor command contract

**Statement:** `seuil doctor` SHALL run every check, print one line per check, exit 0 when all pass, 1 when any blocking check fails, and 2 on an internal error.
**Traces to:** UR-002, UR-007
**Priority:** Must

Blocking checks: BlueZ reachable on D-Bus, adapter powered, PipeWire socket present, credentials present, CoC PSM observed. Advisory checks: bluetoothd experimental interfaces, user unit enabled, SteamOS/Deck detected.

##### Scenario: Healthy system

- **GIVEN** BlueZ reachable, adapter powered, PipeWire socket present, valid credentials, and a parsed advertisement carrying a CoC PSM
- **WHEN** the user runs `seuil doctor`
- **THEN** the command prints one line per check, every line reports pass, and the exit code is 0

##### Scenario: Credentials absent is blocking

- **GIVEN** no `~/.config/seuil/credentials.json`
- **WHEN** the user runs `seuil doctor`
- **THEN** the credentials check prints a blocking failure that names the Desktop Mode setup path
- **AND** the exit code is 1

##### Scenario: PSM reported as observed

- **GIVEN** the latest advertisement carries PSM 0x0081 (129)
- **WHEN** the user runs `seuil doctor`
- **THEN** the PSM line reports the observed 0x0081 and notes 128 as the default constant
- **AND** the line does not fail merely because the value differs from the default

##### Scenario: PSM check fails on connect failure

- **GIVEN** the observed PSM whose CoC connect fails
- **WHEN** the user runs `seuil doctor`
- **THEN** the PSM check fails naming the connect failure
- **AND** the exit code is 1

##### Scenario: Internal error

- **GIVEN** the doctor's own machinery fails, for example an unrecoverable I/O error in its check runner
- **WHEN** the user runs `seuil doctor`
- **THEN** the command prints an internal-error line naming the failing subsystem and exits 2

#### 2.2 FR-002: Prebuilt install path

**Statement:** The installer SHALL provide a prebuilt path (`install.sh --from-release`) that downloads the release artifact into `~/.local/bin` without invoking any compiler or package manager.
**Traces to:** UR-001
**Priority:** Must

##### Scenario: Fresh Deck install

- **GIVEN** a stock SteamOS Deck with network access and no Rust toolchain
- **WHEN** the user runs `install.sh --from-release`
- **THEN** the binary lands at `~/.local/bin/seuil`, is executable, and no compiler or package manager ran

##### Scenario: Download failure

- **GIVEN** the release URL is unreachable or the checksum does not match
- **WHEN** the user runs `install.sh --from-release`
- **THEN** the installer exits non-zero with a clear message and leaves no partial executable in `~/.local/bin`

#### 2.3 FR-003: User unit survives session changes

**Statement:** The user service SHALL stay started across a Gaming Mode to Desktop Mode session change and SHALL start on a pure Gaming Mode boot, waiting for Bluetooth readiness instead of exiting when BlueZ is not yet up.
**Traces to:** UR-001
**Priority:** Must

##### Scenario: Mode round trip

- **GIVEN** the service is active in Gaming Mode
- **WHEN** the user switches to Desktop Mode and later back to Gaming Mode
- **THEN** the service remains active throughout or restarts itself within its unit policy, and the daemon is functional after the switch

##### Scenario: Bluetooth not ready at login

- **GIVEN** the user manager starts the unit before bluetoothd is ready
- **WHEN** the daemon starts and the adapter is not yet powered
- **THEN** the daemon waits with backoff instead of exiting, and proceeds once BlueZ is reachable

#### 2.4 FR-004: Optional dependency degradation

**Statement:** Missing optional runtime tools SHALL degrade only the matching feature with a clear persistent warning, and a failing tool invocation SHALL be distinguished from a missing service record.
**Traces to:** UR-002, UR-005
**Priority:** Must

##### Scenario: sdptool missing

- **GIVEN** SteamOS, whose bluez-utils ships no sdptool
- **WHEN** the daemon starts
- **THEN** startup completes, the SDP-dependent step is skipped, and a warning names sdptool as absent

##### Scenario: sdptool fails, service record exists

- **GIVEN** sdptool present but its local SDP query exits non-zero because bluetoothd runs without the compatibility flag
- **WHEN** the daemon runs the SDP step
- **THEN** the warning names the compatibility requirement rather than reporting the service record as absent

##### Scenario: Audio probe tools missing

- **GIVEN** pactl or playerctl not installed
- **WHEN** the daemon runs and the user runs doctor
- **THEN** both report that audio activity detection is degraded or disabled for that source

#### 2.5 FR-005: BlueZ drop-in printed, flag-gated write

**Statement:** Setup SHALL print the optional BlueZ experimental drop-in content and the exact privileged command that installs it, SHALL write `/etc` only behind an explicit flag, and SHALL include the SteamOS `/etc` allowlist caveat in the printed text.
**Traces to:** UR-001, UR-002
**Priority:** Should

##### Scenario: Default run prints only

- **GIVEN** setup runs without the explicit flag
- **WHEN** the BlueZ step executes
- **THEN** setup prints the override.conf content and the exact sudo install command, writes nothing under `/etc`, and notes that SteamOS keeps `/etc` files only via its migration allowlist

##### Scenario: Explicit flag writes

- **GIVEN** the user passes the explicit flag
- **WHEN** setup runs
- **THEN** the privileged command executes, and a later doctor run reports the experimental flag state

#### 2.6 FR-006: Portable release artifact

**Statement:** The release pipeline SHALL produce an x86_64-unknown-linux-gnu artifact built on a Debian 11 (glibc 2.31) baseline with rustls so no OpenSSL links, verified to run on glibc 2.31 or newer.
**Traces to:** UR-001
**Priority:** Must

##### Scenario: Pipeline verification passes

- **GIVEN** the release workflow builds the artifact in its Debian 11 baseline container
- **WHEN** the linkage check runs
- **THEN** it lists only basic system libraries compatible with glibc 2.31, no OpenSSL, and the job succeeds

##### Scenario: Linkage check fails

- **GIVEN** a dependency change pulls in a library newer than the baseline
- **WHEN** the linkage check runs
- **THEN** the release job fails rather than shipping an artifact that will not load on SteamOS

#### 2.7 FR-007: Deck documentation and decision record

**Statement:** The README SHALL document the Steam Deck install path and the sprint SHALL record the SteamOS install architecture in a numbered decision record under `docs/decisions/`.
**Traces to:** UR-001, UR-002
**Priority:** Must

##### Scenario: Reader follows the README

- **GIVEN** a fresh Deck and the README
- **WHEN** the reader follows the Steam Deck section
- **THEN** they reach a doctor-verified running service without leaving `$HOME` and know first-run setup belongs in Desktop Mode

##### Scenario: Decision recorded

- **GIVEN** the sprint completes
- **WHEN** a contributor looks for why the install layout and drop-in policy look the way they do
- **THEN** the numbered decision record states the settled choices with their rationale

##### Scenario: Documentation missing

- **GIVEN** the sprint's changes landed
- **WHEN** the README's Steam Deck section or the numbered decision record under `docs/decisions/` is absent
- **THEN** the requirement fails acceptance with the missing artifact named

#### 2.8 FR-008: Dual-reading LTV parser, malformed-frame safety

**Statement:** The manufacturer-data parser SHALL accept payloads whose format byte validates at either offset 2 or offset 3, SHALL reject only when both readings fail, and SHALL survive truncated or malformed records without panicking and without discarding valid records elsewhere in the buffer.
**Traces to:** UR-005
**Priority:** Must

##### Scenario: Offset-3 reading accepted

- **GIVEN** manufacturer data `02 18 00 01 00 80 07 48 00 48 00` (11 bytes; format byte 0x01 at offset 3, context bytes at offsets 4 to 8, fallback audio byte at 9, per docs/PROTOCOL_SPEC.md sections 2.2, 2.5, and 2.6)
- **WHEN** the parser runs
- **THEN** the payload decodes to a device context with CoC PSM 0x0080 (128), DS 0x07, NS 0x48, and F 0x00
- **AND** the audio state is Streaming (fallback anchor byte 9 = 0x48)

##### Scenario: Offset-2 reading accepted

- **GIVEN** the same logical payload with the format byte at offset 2: `02 18 01 00 00 80 07 48 00 48 00` (the original-findings reading recorded in docs/PROTOCOL_SPEC.md section 2.8)
- **WHEN** the parser runs
- **THEN** the payload decodes to the same device context (CoC PSM 0x0080, DS 0x07, NS 0x48, F 0x00) and audio state Streaming as the offset-3 reading, rather than being rejected

##### Scenario: Recoverable malformed record skipped

- **GIVEN** a buffer whose first LTV record is malformed without overrunning the buffer end (for example a zero-length record) and whose later records include a valid type 1 record
- **WHEN** the parser walks the buffer
- **THEN** the walk skips the malformed record and still parses the later valid type 1 record, with no panic

##### Scenario: Overrunning record ends the walk safely

- **GIVEN** a record whose declared length overruns the buffer end
- **WHEN** the walk encounters it
- **THEN** the walk ends gracefully with no panic
- **AND** any type 1 record already decoded before the overrun remains in the parse result

##### Scenario: Garbage payload

- **GIVEN** random bytes prefixed with a plausible Samsung header
- **WHEN** the parser runs
- **THEN** parsing returns rejection without panicking

##### Scenario: Account-bound audio-state anchor

- **GIVEN** an account-bound advertisement whose type 1 record carries NS 0x48 at the record-local anchor (body_start + 3, docs/PROTOCOL_SPEC.md section 2.5)
- **WHEN** the parser runs
- **THEN** the audio state is Streaming
- **AND** the same record with NS 0x08 parses Idle
- **AND** the same record with NS 0x00 parses Disconnected

##### Scenario: Fallback audio-state anchor

- **GIVEN** an unbound advertisement whose account-bound parse is unavailable, with manufacturer-data byte 9 equal to 0x48 (masked 0xF8, docs/PROTOCOL_SPEC.md sections 2.5 and 2.6)
- **WHEN** the parser runs
- **THEN** the audio state is Streaming
- **AND** byte 9 equal to 0x08 parses Idle
- **AND** byte 9 equal to 0x18 parses Disconnected

#### 2.9 FR-009: Suspend, resume, and power-off lifecycle

**Statement:** On suspend (logind PrepareForSleep true) and on adapter power-off, the daemon SHALL tear down CoC channels and stop scanning and advertising; on wake or power-on it SHALL re-initialize each session exactly once, with no duplicate advertisements, leaked tasks, or stale channel entries.
**Traces to:** UR-005
**Priority:** Must

##### Scenario: Suspend and wake

- **GIVEN** the daemon running with one advertisement, one discovery session, and one CoC channel
- **WHEN** the system suspends and later wakes
- **THEN** teardown closed the channel and stopped scan and advertising, and after wake exactly one advertisement, one discovery session, and one redial attempt exist

##### Scenario: Adapter power toggle

- **GIVEN** the daemon running
- **WHEN** the adapter powers off and on again
- **THEN** the daemon reaches the same clean state as after a wake, without needing a service restart

##### Scenario: Rapid sleep and wake flapping

- **GIVEN** repeated quick suspend and wake cycles
- **WHEN** the cycles settle
- **THEN** the daemon converges to exactly one active advertisement and one discovery session, with no leaked tasks

#### 2.10 FR-010: Dwell and connect backoff

**Statement:** The daemon SHALL enforce a 10 s minimum dwell between handoff requests and an exponential CoC connect backoff starting at 1 s and capped at 60 s, both configurable in config.toml with those defaults.
**Traces to:** UR-003
**Priority:** Must

##### Scenario: Second request inside the dwell

- **GIVEN** a handoff request sent less than 10 s ago
- **WHEN** a new trigger fires
- **THEN** the new request is suppressed and logged as dwell-blocked

##### Scenario: Request after the dwell

- **GIVEN** the last handoff request was 10 s ago or more
- **WHEN** a new trigger fires
- **THEN** the request proceeds

##### Scenario: Backoff sequence on repeated connect failures

- **GIVEN** the phone is unreachable
- **WHEN** connect attempts repeatedly fail
- **THEN** retry delays follow 1, 2, 4, and so on, capped at 60 s

##### Scenario: Custom configuration honored

- **GIVEN** config.toml sets a different dwell or backoff
- **WHEN** the daemon runs
- **THEN** the configured values are used

#### 2.11 FR-011: Dial and advertisement authenticity

**Statement:** The daemon SHALL pair and dial only advertisements from the configured phone address and SHALL verify inbound advertisement checksums against the account fingerprint before acting on them.
**Traces to:** UR-005
**Priority:** Must

##### Scenario: Spoofed advertisement ignored

- **GIVEN** a 0x0075 advertisement with a type 1 record from an address other than the configured phone
- **WHEN** the scan handler processes it
- **THEN** no pairing and no dial occur, and a warning names the rejected address

##### Scenario: Bad checksum ignored

- **GIVEN** an advertisement from the configured phone whose checksum does not match the account fingerprint
- **WHEN** the scan handler processes it
- **THEN** the payload is not acted on

##### Scenario: Valid advertisement acted on

- **GIVEN** a type 1 advertisement from the configured phone whose checksum matches the account fingerprint
- **WHEN** the dial path evaluates it
- **THEN** pairing and dial proceed under the timing requirements

#### 2.12 FR-012: Event-loop panic elimination

**Statement:** Background event loops SHALL handle address-parse and crypto-size failures as errors, bound keepalive and frame reads with timeouts configurable in config.toml (default 10 s each), and cap per-peer bookkeeping maps at a configurable limit (config.toml, default 256 entries).
**Traces to:** UR-005
**Priority:** Must

##### Scenario: Malformed address string

- **GIVEN** an address string that fails to parse reaches an event handler
- **WHEN** the handler processes it
- **THEN** the failure is logged as an error and the loop and its task continue

##### Scenario: Stalled peer

- **GIVEN** a CoC peer stops responding mid-frame
- **WHEN** the read timeout expires at its configured limit (default 10 s)
- **THEN** the channel tears down cleanly and the map entry is removed

##### Scenario: Crypto-size failure contained

- **GIVEN** a crypto operation receives a wrong-size key or nonce
- **WHEN** the handler processes it
- **THEN** the failure is logged as an error and the loop continues without panicking

##### Scenario: Keepalive timeout tears down

- **GIVEN** a CoC peer that stops acknowledging keepalive writes
- **WHEN** the keepalive timeout expires at its configured limit (default 10 s)
- **THEN** the channel tears down cleanly and its map entry is removed

##### Scenario: Rotating spoofed addresses

- **GIVEN** hours of advertisements from rotating random addresses
- **WHEN** the bookkeeping maps are inspected
- **THEN** their size never exceeds the per-peer bookkeeping cap configured in config.toml, defaulting to 256 entries

#### 2.13 FR-013: SPP transport wired

**Statement:** The daemon SHALL route auto switch traffic per the settled transport split: phone-directed commands over the BLE L2CAP CoC and Buds opcodes (SET_SEAMLESS_CONNECTION and its acknowledgement) over RFCOMM SPP, with the Buds SPP frame parser rejecting short or malformed frames without panicking.
**Traces to:** UR-003, UR-005
**Priority:** Must

##### Scenario: Phone-directed commands ride the CoC

- **GIVEN** the CoC established by the account handshake
- **WHEN** a BUDS_SWITCH request or response, ready event, or get-device-state flows
- **THEN** it travels on the BLE CoC channel
- **AND** no phone-directed command travels over SPP

##### Scenario: Seamless handoff delivered

- **GIVEN** a yield to the phone completes
- **WHEN** the handoff action runs
- **THEN** SET_SEAMLESS_CONNECTION reaches the Buds over SPP and the acknowledgement is processed

##### Scenario: Malformed SPP frame

- **GIVEN** an SPP frame with a declared size under 2 or a truncated body
- **WHEN** the frame parser runs
- **THEN** the frame is dropped with a warning and the session continues without panic

#### 2.14 FR-014: Concurrency correctness

**Statement:** The daemon SHALL prevent concurrency faults with observable outcomes: a closed channel leaves no entry that blocks future dials to that peer, one peer's blocked channel does not stall other peers, and a hung connect attempt does not accumulate duplicates.
**Traces to:** UR-005
**Priority:** Must

##### Scenario: Closed channel does not block redial

- **GIVEN** a dial whose channel closes immediately
- **WHEN** the same peer is dialed again
- **THEN** the new dial proceeds, not blocked by the old one's state

##### Scenario: Backpressure does not stall unrelated peers

- **GIVEN** one peer's channel blocked or saturated
- **WHEN** another peer's traffic flows
- **THEN** the other peer is served

##### Scenario: Hung attempt does not duplicate

- **GIVEN** a first connect attempt that has not completed
- **WHEN** the retry timer fires
- **THEN** no duplicate attempt runs concurrently
- **AND** a later retry proceeds once the first attempt resolves or times out

#### 2.15 FR-015: Scan and advertiser supervision

**Statement:** Discovery restarts SHALL stop the previous session before reapplying filters, a rejected discovery filter SHALL produce a visible warning, and the advertiser SHALL retry registration failures with backoff instead of exiting.
**Traces to:** UR-005
**Priority:** Must

##### Scenario: Adapter loss and return

- **GIVEN** the adapter disappears and comes back
- **WHEN** the scan loop restarts
- **THEN** exactly one discovery session is active afterward

##### Scenario: Previous session stopped first

- **GIVEN** a discovery session running when the scan loop restarts
- **WHEN** the restart re-applies the discovery filter and opens a new stream
- **THEN** the previous session was stopped before the filter was re-applied
- **AND** exactly one discovery session is active

##### Scenario: Advertisement registration collision

- **GIVEN** an advertisement re-registration that fails because the previous one is still unregistering
- **WHEN** the advertiser handles the error
- **THEN** it retries with backoff and advertising continues for the process lifetime

##### Scenario: Filter rejection surfaced

- **GIVEN** BlueZ rejects the discovery filter
- **WHEN** the scan loop continues unfiltered
- **THEN** a warning names the rejection instead of silently proceeding

#### 2.16 FR-016: Active-audio peak-window rule

**Statement:** The media monitor SHALL treat a stream as active only while it is RUNNING and its peak stays above -60 dBFS across a 200 ms window, SHALL exclude capture-side and communication-class streams, and SHALL expose the threshold and window as config.toml keys with those defaults.
**Traces to:** UR-004
**Priority:** Must

##### Scenario: Silent tab is not activity

- **GIVEN** a browser tab holding a RUNNING but digitally silent stream
- **WHEN** the monitor evaluates it
- **THEN** the stream is not active and no handoff request fires

##### Scenario: Real game audio is activity

- **GIVEN** game audio playing above the threshold
- **WHEN** the peak stays above -60 dBFS across the 200 ms window
- **THEN** the stream is active and one media-reason request fires

##### Scenario: Communication stream excluded

- **GIVEN** a voice-chat stream classified as communication or capture
- **WHEN** the monitor evaluates it
- **THEN** it does not count as media activity

##### Scenario: Thresholds configurable

- **GIVEN** config.toml sets a different threshold or window
- **WHEN** the monitor runs
- **THEN** the configured values are used

#### 2.17 FR-017: Call-aware handoff policy

**Statement:** An active HFP call SHALL block media-reason handoffs, call-reason switching SHALL remain allowed during HFP, and the call guard SHALL be scoped to call-reason responses rather than cleared by any response.
**Traces to:** UR-004, UR-003
**Priority:** Must

##### Scenario: Media trigger during a call

- **GIVEN** an active HFP call on the Buds
- **WHEN** local media starts
- **THEN** the media-reason handoff is suppressed

##### Scenario: Call-reason switching during HFP

- **GIVEN** an active HFP call
- **WHEN** a call-reason switch request arrives
- **THEN** it proceeds

##### Scenario: Lost call response does not lock media

- **GIVEN** a call-reason response that never arrives
- **WHEN** media triggers later
- **THEN** media handoffs are not blocked by a blanket timed lock

#### 2.18 FR-018: Probe resilience

**Statement:** Probe or service failures SHALL NOT fabricate activity edges: a failed probe SHALL hold the last known state rather than emitting a stop followed by a start, probes SHALL be timeout-bounded, and the monitor task SHALL be supervised so its death is visible and recoverable.
**Traces to:** UR-004, UR-005
**Priority:** Must

##### Scenario: Probe tool absent

- **GIVEN** pactl missing from the system
- **WHEN** the monitor runs
- **THEN** one persistent warning is logged, the last known activity state is held, and no stop/start edge pair is emitted

##### Scenario: Probe hangs

- **GIVEN** a probe subprocess that never returns
- **WHEN** its timeout expires
- **THEN** the tick completes and later ticks continue

##### Scenario: Monitor task dies

- **GIVEN** the media monitor task exits or panics
- **WHEN** the supervisor notices
- **THEN** the task is restarted and an error is logged

##### Scenario: PipeWire restart recovery

- **GIVEN** the PipeWire daemon restarting while the daemon runs
- **WHEN** the monitor reconnects after the restart
- **THEN** activity evaluation resumes without a fabricated edge pair

#### 2.19 FR-019: Release and pull ordering

**Statement:** On a release request the daemon SHALL verify the pause succeeded and complete profile teardown before answering the phone, and on a granted switch it SHALL retry the A2DP connect; a call-reason response SHALL NOT trigger an A2DP pull.
**Traces to:** UR-003, UR-004
**Priority:** Must

##### Scenario: Pause failure is reported

- **GIVEN** MPRIS pause fails during a release
- **WHEN** the release completes
- **THEN** the reply to the phone reflects the failure rather than claiming success

##### Scenario: Teardown before reply

- **GIVEN** a release with A2DP and HFP links up
- **WHEN** the daemon answers the phone
- **THEN** the profile disconnects have completed or their failure is reported in the reply's result path

##### Scenario: A2DP pull retries

- **GIVEN** a granted media switch whose first A2DP connect fails or is slow
- **WHEN** the connect retries
- **THEN** bounded retries occur before giving up with a warning

##### Scenario: Call-reason grant leaves media alone

- **GIVEN** the phone grants a call-reason switch
- **WHEN** the grant is processed
- **THEN** no A2DP pull is initiated

#### 2.20 FR-020: Credential key integrity

**Statement:** A missing, unreadable, or wrong-length credentials.key SHALL fail credential loading with a specific error and no silent regeneration, and credential writes SHALL be atomic, durable across a crash, and resilient to stale temp files.
**Traces to:** UR-006, UR-005
**Priority:** Must

##### Scenario: Key deleted, envelope remains

- **GIVEN** `credentials.json` present and `credentials.key` deleted
- **WHEN** credentials load
- **THEN** loading fails with an error naming the key file, and no new key is written

##### Scenario: Key unreadable

- **GIVEN** `credentials.key` with permissions or ownership that deny reading
- **WHEN** credentials load
- **THEN** loading fails naming the key file, and no new key is written

##### Scenario: Key wrong length

- **GIVEN** `credentials.key` containing a length other than 32 bytes
- **WHEN** credentials load
- **THEN** loading fails naming the length mismatch, and no new key is written

##### Scenario: Crash mid-save

- **GIVEN** a save interrupted by a crash or power loss
- **WHEN** the daemon next loads
- **THEN** the previous envelope is intact and decryptable

##### Scenario: Stale temp file

- **GIVEN** a leftover temp file from a crashed save
- **WHEN** the next save runs
- **THEN** the save succeeds without manual cleanup

#### 2.21 FR-021: Credential secrecy

**Statement:** The daemon and setup SHALL NOT print account keys or tokens to stdout or logs, and debug formatting of credential structures SHALL redact secret fields.
**Traces to:** UR-006
**Priority:** Must

##### Scenario: Auth run prints no key material

- **GIVEN** a successful account authentication or refresh
- **WHEN** its output is inspected
- **THEN** no account key, token, or private key material appears in stdout or logs

##### Scenario: Debug formatting redacted

- **GIVEN** a credential structure printed with debug formatting
- **WHEN** the output is inspected
- **THEN** secret fields are redacted

#### 2.22 FR-022: Config and unit write integrity

**Statement:** config.toml and the systemd unit SHALL be written atomically, the config directory SHALL carry owner-only permissions, and an invalid config.toml SHALL abort startup with the parse error instead of silently using defaults.
**Traces to:** UR-005, UR-006
**Priority:** Must

##### Scenario: Crash during config save

- **GIVEN** a config write interrupted by a crash
- **WHEN** setup or the daemon next reads the file
- **THEN** the previous content is intact

##### Scenario: Interrupted unit write

- **GIVEN** a systemd unit write interrupted by a crash
- **WHEN** setup next reads the unit file
- **THEN** the previous unit content is intact

##### Scenario: TOML typo aborts

- **GIVEN** a config.toml with a syntax error
- **WHEN** the daemon starts
- **THEN** startup aborts with an error naming the file and the parse failure

##### Scenario: Directory permissions

- **GIVEN** a fresh install
- **WHEN** setup creates the config directory
- **THEN** the directory is owner-only (0700) even when a parent defaults to group or world readable

#### 2.23 FR-023: Token, certificate, and session lifecycle

**Statement:** The daemon SHALL refresh expiring tokens at runtime, re-enroll when the handshake indicates invalid credentials with bounded retries and a user-visible escalation, re-acquire its Bluetooth session after a bluetoothd restart, and back off pairing failures.
**Traces to:** UR-005, UR-006
**Priority:** Must

##### Scenario: Token refresh at runtime

- **GIVEN** a service token whose expiry enters the 120-second refresh margin while the daemon runs
- **WHEN** the refresh path executes
- **THEN** the token is refreshed and persisted without user action
- **AND** a token whose expiry lies outside the margin does not trigger a refresh

##### Scenario: Certificate rotation escalates

- **GIVEN** the stored certificate rejected by the handshake
- **WHEN** retries exhaust their bound
- **THEN** a clear escalation tells the user to rerun setup instead of retrying silently forever

##### Scenario: bluetoothd restart recovery

- **GIVEN** bluetoothd restarted
- **WHEN** the daemon notices the dead session
- **THEN** it re-acquires the adapter and session with backoff and resumes scanning and advertising

##### Scenario: Pairing failures back off

- **GIVEN** repeated pairing failures, for example a permissions problem
- **WHEN** the retry loop runs
- **THEN** delays grow rather than retrying flatly, and the failure is visible

#### 2.24 FR-024: Test coverage of the settled boundaries

**Statement:** The test suite SHALL cover malformed LTV and L2CAP frames under both format-byte readings, the audio-state anchor on short and long advertisements, the dwell and backoff boundaries, sleep/wake state resets, the active-audio filter rule, and the doctor exit contract, and every existing test SHALL keep passing.
**Traces to:** UR-007
**Priority:** Must

##### Scenario: Settled boundaries covered

- **GIVEN** the settled decisions
- **WHEN** the test suite runs
- **THEN** each boundary has a test: malformed LTV frames and malformed L2CAP frames under both format-byte readings, the audio-state anchor on short and long advertisements, the 10 s dwell edge, the 1 s and 60 s backoff edges, sleep/wake state convergence, the peak-window rule, and doctor exit codes

##### Scenario: Regression held

- **GIVEN** the existing test suite
- **WHEN** the hardening changes land
- **THEN** every existing test still passes

##### Scenario: Boundary uncovered

- **GIVEN** a settled boundary with no citing test
- **WHEN** the coverage listing runs
- **THEN** the requirement fails acceptance naming the uncovered boundary

#### 2.25 FR-025: Verification gates

**Statement:** The sprint SHALL be verified by cargo check, cargo clippy with warnings denied, cargo test, and a release build, all passing; the live phone gate is reported pending as a separate pre-merge criterion.
**Traces to:** UR-007
**Priority:** Must

##### Scenario: All gates green

- **GIVEN** the implementation complete
- **WHEN** the verification suite runs
- **THEN** cargo check, clippy with -D warnings, cargo test, and the release build all exit 0 with zero warnings

##### Scenario: A gate fails

- **GIVEN** any gate failing or warning
- **WHEN** the failure is observed
- **THEN** the producing step fixes it before the sprint is called complete, and the live phone gate is reported as pending, not silently passed

### 3. Non-functional requirements

#### 3.1 Performance

| ID | Requirement | Traces to | Metric |
|----|-------------|-----------|--------|
| NFR-001 | The media monitor SHALL settle an activity-state change within 1 s of the underlying stream change at default settings. | FR-016 | Detection latency bound, testable with a synthetic stream |

#### 3.2 Security

| ID | Requirement | Traces to | Standard/Compliance |
|----|-------------|-----------|---------------------|
| NFR-002 | The daemon SHALL keep account keys, tokens, and certificates out of stdout, logs, and debug output in every code path. | BR-004 | Repository credential policy (AES-256-GCM envelope, v1) |

#### 3.3 Reliability and availability

| ID | Requirement | Traces to | Metric |
|----|-------------|-----------|--------|
| NFR-003 | The daemon SHALL expose no panic path reachable from malformed BLE, L2CAP, or SPP input. | BR-001 | Malformed-frame test set, all passing |
| NFR-004 | The daemon SHALL re-establish scanning, advertising, and its Bluetooth session within 60 s of bluetoothd becoming reachable again after a restart. | FR-009, FR-023 | Capped backoff, worst case 60 s |

#### 3.4 Usability

| ID | Requirement | Traces to | Metric |
|----|-------------|-----------|--------|
| NFR-005 | Doctor output SHALL be one line per check, each naming the check, its result, and for failures the next action. | UR-002 | Exit-code and output tests |

#### 3.5 Portability

| ID | Requirement | Traces to | Metric |
|----|-------------|-----------|--------|
| NFR-006 | All user-installed state SHALL live under `$HOME` at the settled paths: binary at `~/.local/bin`, config and credentials at `~/.config/seuil/`, user unit at `~/.config/systemd/user/`; any suggested `/etc` change documents the SteamOS allowlist caveat; the portable artifact runs on glibc 2.31 or newer with no OpenSSL linkage. | BR-002 | Path inventory plus linkage check in CI |

#### 3.6 Maintainability

| ID | Requirement | Traces to | Metric |
|----|-------------|-----------|--------|
| NFR-007 | cargo clippy on all targets with warnings denied SHALL pass with zero warnings. | UR-007 | Gate exit code |

### 4. Scope

#### In scope (system behaviors)

- Doctor, prebuilt install, unit survival, dependency degradation, drop-in printing, portable artifact, documentation, and the decision record.
- Dual-reading parser, suspend and power lifecycle, dwell and backoff, dial authenticity, panic elimination, SPP wiring, concurrency, scan supervision.
- Peak-window audio rule, call policy, probe resilience, release and pull ordering.
- Credential integrity and secrecy, config and unit write integrity, token and session lifecycle.
- Tests and the four verification gates.

#### Out of scope (system exclusions)

| Excluded item | Reason | Deferred to |
|---------------|--------|-------------|
| Executing the live phone acceptance gate | No hardware attached this sprint; decision 001 keeps it the pre-merge criterion | Pre-merge live gate |
| AdvertisementMonitor1-based scanning | Needs experimental BlueZ interfaces the current code path does not use | Future scanner rework |
| musl static artifact | Settled on the gnu baseline target | Deferred |
| docs/PROTOCOL_SPEC.md quality overhaul | Intake findings recorded, not adopted this sprint | Separate documentation pass |
| Phone-side protocol behavior | Samsung's protocol is fixed; the Linux peer adapts | Never |

### 5. Constraints

- Rust 2024 edition, bluer 0.17, zbus 5, tokio; the Bluetooth stack is BlueZ over D-Bus and kernel L2CAP.
- The transport split is fixed: phone commands over the BLE CoC, Buds opcodes over SPP (docs/PROTOCOL_SPEC.md section 1).
- Install layout is fixed per the settled decision; no path moves.
- SteamOS immutability: no rootfs writes, `/etc` only via the documented caveat.

### 6. Traceability matrix

| BR | UR | FR | NFR | Status |
|----|----|----|-----|--------|
| BR-001 | UR-003, UR-005 | FR-004, FR-008, FR-009, FR-010, FR-011, FR-012, FR-013, FR-014, FR-015, FR-017, FR-018, FR-019, FR-020, FR-022, FR-023 | NFR-003, NFR-004 | Draft |
| BR-002 | UR-001 | FR-002, FR-003, FR-005, FR-006, FR-007 | NFR-006 | Draft |
| BR-003 | UR-002, UR-007 | FR-001, FR-004, FR-005, FR-007, FR-024, FR-025 | NFR-005, NFR-007 | Draft |
| BR-004 | UR-006 | FR-020, FR-021, FR-022, FR-023 | NFR-002 | Draft |
| BR-005 | UR-003, UR-004 | FR-010, FR-013, FR-016, FR-017, FR-018, FR-019 | NFR-001 | Draft |

Orphans: none. Dead ends: none.

### 7. Glossary

| Term | Definition |
|------|-----------|
| dwell | Minimum time between handoff requests, default 10 s |
| backoff | CoC connect retry delay doubling from 1 s to a 60 s cap |
| format byte | The manufacturer-data byte carrying type and format flags; readable at offset 2 or 3 until a capture settles it |
| peak-window rule | RUNNING plus peak above -60 dBFS sustained over 200 ms |
| communication-class stream | PipeWire stream classified for voice or call use |
| call guard | State that suppresses media handoffs during a call, scoped to call-reason responses |
| stale sender | A channel-map entry whose task has exited, blocking redials |
| in-flight marker | Bookkeeping that a connect attempt is running, preventing duplicate attempts |

### 8. Revision history

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-11-18 | [Author] | Initial draft from the four audits and settled decisions |
