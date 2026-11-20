# Task Plan: seuil SteamOS hardening sprint

**Target Language:** Rust  
**Target Framework:** tokio + bluer + zbus (async Linux daemon)  
**Generated:** 2026-11-18 21:54:37

---

## Specification Summary

- **Spec IDs:** spec-seuil-doctor, spec-steamos-deck-support, spec-transport-lifecycle-hardening, spec-media-activity-filtering, spec-credential-config-integrity, spec-hardening-test-suite (all under `specs/`)
- **Linked Requirements:** FR-001 to FR-025, NFR-001 to NFR-007, BR-001 to BR-005, UR-001 to UR-007
- **Use Cases:** UC-001 install on a fresh Deck, UC-002 diagnose a broken setup, UC-003 keep the Buds during an active game, UC-004 survive suspend and resume

Harden the daemon's transport, audio, and credential paths against the audited fault set, add the `seuil doctor` diagnostic and SteamOS install support, and verify with the four cargo gates.

---

## Acceptance Criteria

The settled boundaries every step traces to; full scenarios live in the specs and FR-NFR document.

| Scenario | GIVEN | WHEN | THEN |
|---|---|---|---|
| Format-byte offset-2 reading accepted | a payload whose format byte validates at offset 2 | the parser runs | the payload parses like the offset-3 reading |
| Recoverable record skipped | a zero-length record before a valid type 1 record | the walk continues | the malformed record is skipped and the later valid record still parses |
| Overrun ends the walk | a record whose declared length overruns the buffer | the walk encounters it | the walk ends safely with any earlier decoded record preserved, no panic |
| Suspend and wake converge | one advertisement, one discovery session, one CoC channel | suspend then wake | exactly one of each exists afterward, exactly one redial attempt follows the wake, no leaked tasks |
| Dwell blocks rapid requests | a handoff request less than 10 s ago | a new trigger fires | the request is suppressed and logged |
| Backoff sequence | the phone unreachable | dials repeatedly fail | delays 1, 2, 4, up to the 60 s cap |
| Silent tab not activity | a RUNNING stream below -60 dBFS across 200 ms | the monitor evaluates | no handoff request fires |
| Communication stream excluded | a voice-chat or capture stream | the monitor evaluates | not counted as media activity |
| HFP blocks media reason | an active HFP call | local media starts | the media-reason handoff is suppressed |
| Doctor contract | blocking and advisory sets as settled | `seuil doctor` runs | one line per check, exit 0/1/2 per the contract |
| PSM observed | an advertisement carrying PSM 0x0081 (129) | doctor runs | reported as observed without failing on the difference; a failed CoC connect fails the check |
| sdptool missing | SteamOS without sdptool | the daemon starts | startup completes with a warning, doctor reports the degradation |
| Key missing fails load | envelope present, key deleted | credentials load | load fails naming the key file, no regeneration |
| Invalid config aborts | a config.toml syntax error | the daemon starts | startup aborts naming the file and parse failure |
| Drop-in printed only | setup without the explicit flag | the BlueZ step runs | content and sudo command print, nothing written under /etc, allowlist caveat shown |
| Gates green | implementation complete | the verification suite runs | all four gates exit 0 with zero warnings |
| Transport split | a handoff exchange in progress | traffic flows | phone-directed commands ride the BLE CoC and Buds opcodes ride SPP |

---

## Implementation Steps

### Step 1: Doctor module and CLI wiring

- **Files:** `daemon/src/doctor.rs` (create), `daemon/src/main.rs` (modify)
- **Satisfies:** [spec-seuil-doctor -> FR-001 -> all five scenarios], [NFR-005]
- **Code references:** `languages/rust.md`, `logging-standards.md`
- **Notes:** Blocking set (BlueZ reachable, adapter powered, PipeWire socket, credentials, CoC PSM observed) and advisory set (experimental interfaces, unit enabled, SteamOS detected) per the settled contract; PSM reported as observed with 128 as default; every probe timeout-bounded; missing tools degrade to failed lines, never aborts.

### Step 2: SteamOS-safe setup and unit

- **Files:** `daemon/src/setup.rs` (modify; preserve the pre-existing local modifications in the working tree)
- **Satisfies:** [spec-steamos-deck-support -> FR-003 -> mode round trip and bluetooth-not-ready], [FR-004 -> all three scenarios], [FR-005 -> both scenarios], [FR-022 -> setup-side scenarios]
- **Code references:** `languages/rust.md`, `error-handling-standards.md`
- **Notes:** Atomic config and unit writes with a 0700 config directory; unit text drops `PartOf=graphical-session.target` and orders only against user-scope targets; sdptool absence is non-fatal and its non-zero exit is distinguished from a missing service record; pactl and playerctl presence checks; the BlueZ drop-in prints with the flag-gated write and the /etc allowlist caveat.

### Step 3: Prebuilt install path and release pipeline

- **Files:** `install.sh` (modify), `.github/workflows/release.yml` (modify)
- **Satisfies:** [spec-steamos-deck-support -> FR-002 -> both scenarios], [FR-006 -> both scenarios], [NFR-006 -> path inventory at the settled paths]
- **Code references:** `languages/rust.md`
- **Notes:** `install.sh --from-release` downloads and verifies the release artifact into `~/.local/bin` with no toolchain use; the release workflow gains a Debian 11 (glibc 2.31) build job with rustls and an ldd linkage check that fails the job on any non-basic library. The step also delivers the path inventory proving all persistent user-installed state lives under `$HOME` at the settled locations (binary at `~/.local/bin`, config and credentials at `~/.config/seuil/`, user unit at `~/.config/systemd/user/`); the BlueZ `/etc` drop-in is accounted separately as an explicitly requested, flag-gated write that is not part of user-installed state and documents the SteamOS allowlist caveat.

### Step 4: Documentation and decision record

- **Files:** `README.md` (modify), `docs/decisions/003-steamos-deck-support.md` (create)
- **Satisfies:** [spec-steamos-deck-support -> FR-007 -> all three scenarios]
- **Code references:** none (documentation only)
- **Notes:** README gains the Steam Deck section (Desktop Mode setup, prebuilt path, doctor verification); the decision record follows the repo's docs/decisions numbering and states the settled layout, drop-in policy, and build-target choice.

### Step 5: Parser tolerance

- **Files:** `daemon/src/ble/mod.rs` (modify), `daemon/src/protocol/mod.rs` (modify)
- **Satisfies:** [spec-transport-lifecycle-hardening -> FR-008 -> all seven scenarios], [NFR-003 -> no panic on malformed input]
- **Code references:** `languages/rust.md`, `error-handling-standards.md`
- **Notes:** Accept the format byte at offset 2 or 3, reject only when both fail; keep the daemon's current offset-3 reading primary; skip malformed records without discarding reachable valid records; no panic on garbage input.

### Step 6: Lifecycle supervisor

- **Files:** `daemon/src/main.rs` (modify), `daemon/src/ble/mod.rs` (modify)
- **Satisfies:** [spec-transport-lifecycle-hardening -> FR-009 -> all three scenarios], [FR-023 -> bluetoothd-restart scenario], [NFR-004]
- **Code references:** `languages/rust.md`, `patterns/rust/background-job.md`
- **Notes:** Subscribe to logind PrepareForSleep over the system bus and watch the adapter Powered property; teardown closes CoC channels and stops scan and advertising; re-initialization is idempotent (epoch counter) so flapping converges; adapter re-acquisition uses the capped backoff, with scanning, advertising, and the Bluetooth session recovered within NFR-004's 60-second bound after bluetoothd becomes reachable.

### Step 7: CoC channel manager correctness

- **Files:** `daemon/src/main.rs` (modify), `daemon/src/ble/coc_session.rs` (modify), `daemon/src/ble/l2cap.rs` (modify)
- **Satisfies:** [spec-transport-lifecycle-hardening -> FR-010 -> backoff scenarios], [FR-012 -> all five scenarios], [FR-014 -> all three scenarios], [FR-023 -> pairing-failure backoff scenario], [NFR-003 -> no panic on malformed input]
- **Code references:** `languages/rust.md`, `patterns/rust/retry-backoff.md`, `error-handling-standards.md`
- **Notes:** The channel task owns its map entry (insert-before-spawn plus an in-flight marker) so immediate closes leave no stale senders; no lock is held across a blocking await; keepalive and frame reads carry timeouts configurable in config.toml (default 10 s each); connect backoff 1 s doubling to a 60 s cap; MAC parses are errors, not unwraps; per-peer maps are capped at the configurable limit (config.toml, default 256 entries); pairing failures back off with growing delays.

### Step 8: Dial authenticity

- **Files:** `daemon/src/ble/mod.rs` (modify), `daemon/src/main.rs` (modify)
- **Satisfies:** [spec-transport-lifecycle-hardening -> FR-011 -> all three scenarios]
- **Code references:** `languages/rust.md`, `logging-standards.md`
- **Notes:** Pair and dial only the configured phone address; verify inbound advertisement checksums against the account fingerprint; rejected advertisements log the address.

### Step 9: SPP transport wiring

- **Files:** `daemon/src/rfcomm/mod.rs` (modify), `daemon/src/sdp/mod.rs` (modify), `daemon/src/buds/mod.rs` (modify), `daemon/src/handoff/mod.rs` (modify), `daemon/src/main.rs` (modify)
- **Satisfies:** [spec-transport-lifecycle-hardening -> FR-013 -> all three scenarios], [NFR-003 -> no panic on malformed SPP frames]
- **Code references:** `languages/rust.md`, `error-handling-standards.md`
- **Notes:** Register a BlueZ Profile1 handler so an RFCOMM socket reaches this process; retain the rfcomm sender (currently dropped at bind); deliver SET_SEAMLESS_CONNECTION and process its acknowledgement; guard the Buds frame parser against declared sizes under 2; stop writing the fixed /tmp/seuil-sdp.xml path unguarded. Phone-directed auto switch commands stay on the BLE CoC; only Buds opcodes and their acknowledgements use SPP.

### Step 10: Scan and advertiser supervision

- **Files:** `daemon/src/ble/mod.rs` (modify)
- **Satisfies:** [spec-transport-lifecycle-hardening -> FR-015 -> all four scenarios]
- **Code references:** `patterns/rust/background-job.md`, `languages/rust.md`
- **Notes:** Stop the previous discovery session before reapplying filters; a rejected filter logs a visible warning; the advertiser retries registration failures with backoff instead of exiting; the last_seen duplicate gate is bounded.

### Step 11: Timing config keys

- **Files:** `daemon/src/config.rs` (modify), `daemon/src/handoff/mod.rs` (modify), `daemon/src/main.rs` (modify)
- **Satisfies:** [spec-transport-lifecycle-hardening -> FR-010 -> dwell scenarios], [FR-024 -> dwell and backoff boundary tests]
- **Code references:** `languages/rust.md`
- **Notes:** config.toml gains the dwell key (default 10 s) and the backoff keys (1 s start, 60 s cap); the handoff state machine enforces the dwell with a timestamp; invalid config aborts per FR-022.

### Step 12: Media activity filtering

- **Files:** `daemon/src/media/mod.rs` (modify), `daemon/src/config.rs` (modify)
- **Satisfies:** [spec-media-activity-filtering -> FR-016 -> all four scenarios], [FR-018 -> all four scenarios], [NFR-001]
- **Code references:** `languages/rust.md`, `patterns/rust/background-job.md`, `error-handling-standards.md`
- **Notes:** Classify a stream active only when RUNNING with peak above the configured threshold across the configured window (defaults -60 dBFS, 200 ms); exclude capture-side and communication-class streams; failed probes hold the last known state with a persistent warning and never emit an edge pair; probes are timeout-bounded; the monitor task runs supervised. The step schedules a timed synthetic-stream check for NFR-001's one-second activity-settling bound.

### Step 13: Call policy and release/pull ordering

- **Files:** `daemon/src/main.rs` (modify), `daemon/src/handoff/mod.rs` (modify)
- **Satisfies:** [spec-media-activity-filtering -> FR-017 -> all three scenarios], [FR-019 -> all four scenarios]
- **Code references:** `languages/rust.md`, `error-handling-standards.md`
- **Notes:** The call guard is scoped to call-reason responses instead of a blanket 30-minute lock cleared by any response; a release verifies the pause, completes profile teardown, and only then answers; the A2DP pull retries within bounds; a call-reason grant never pulls A2DP.

### Step 14: Credential and config integrity

- **Files:** `daemon/src/auth/credentials.rs` (modify), `daemon/src/auth/mod.rs` (modify), `daemon/src/auth/browser.rs` (modify), `daemon/src/config.rs` (modify), `daemon/src/main.rs` (modify)
- **Satisfies:** [spec-credential-config-integrity -> FR-020 -> all five scenarios], [FR-021 -> both scenarios], [FR-022 -> daemon-side scenarios], [FR-023 -> token, re-enroll, and pairing-backoff scenarios], [NFR-002]
- **Code references:** `languages/rust.md`, `error-handling-standards.md`, `logging-standards.md`
- **Notes:** A missing or wrong-length key fails the load by name instead of regenerating; saves use unique temp names, file sync, and parent-directory sync; Debug output is redacted; the account key never prints to stdout; the daemon refreshes expiring tokens at runtime and escalates after bounded re-enroll retries; invalid config aborts startup with the parse error; hostname fallback warns instead of silently re-enrolling a new identity.

### Step 15: Black-box tests

- **Files:** `daemon/tests/` (create)
- **Satisfies:** [spec-hardening-test-suite -> FR-024 -> all three scenarios]
- **Owner:** developer-tester (test paths only; the developer never writes test paths)
- **Code references:** `languages/rust.md`
- **Notes:** One test per settled boundary, each citing the FR or scenario id it traces to: malformed LTV and L2CAP frames under both format-byte readings; malformed SPP frames per the transport spec; the audio-state anchor on short and long advertisements; the dwell edge at and past 10 s; the backoff edges at 1 s and the 60 s cap; timeout expiry at the configured defaults (FR-012: keepalive and frame reads, 10 s each); custom-configured dwell and backoff values overriding the defaults (FR-010); sleep/wake state convergence with exactly one redial attempt; adapter power-off and on recovery; the timed bluetoothd-restart recovery test within the 60-second bound; the PipeWire restart recovery test (FR-018, the PipeWire restart recovery scenario in specs/spec-media-activity-filtering.md): the monitor reconnects after a PipeWire restart and activity evaluation resumes without a fabricated stop/start edge pair, holding the last known state during the outage; the NFR-001 detection-latency test with a synthetic stream; the silent-tab, game-audio, and communication-class audio cases; the doctor exit contract and NFR-005's per-check output format (one line per check, the next action named on failures); and the credential and token secrecy checks (NFR-002: no secret output on auth runs, debug formatting redacted); the FR-002 install-failure test (the Download failure scenario in docs/requirements/FR-NFR-seuil-steamos-hardening.md section 2.2, also named in specs/spec-steamos-deck-support.md's traceability): `install.sh --from-release` with an unreachable URL or a checksum mismatch exits non-zero with a clear message and leaves no partial executable; the FR-018 probe-resilience tests beyond the PipeWire restart case (the probe-hang timeout and monitor-task-death scenarios in docs/requirements/FR-NFR-seuil-steamos-hardening.md section 2.18, also named in specs/spec-media-activity-filtering.md's traceability): a probe subprocess that never returns is cut off by its timeout and later ticks continue, and the supervisor restarts a dead monitor task and logs the error; the FR-017 call-policy test, where the call guard blocks only media-reason handoffs during a call while call-reason switching stays allowed; the FR-019 release and pull ordering test, where a release verifies the pause, completes profile teardown, and only then answers, and a call-reason grant never pulls A2DP (call-policy and release/pull ordering tests named in specs/spec-media-activity-filtering.md's traceability); and the FR-020 to FR-023 credential, config, and token lifecycle tests beyond the NFR-002 secrecy checks: the key-missing and wrong-length load failure names the key file with no regeneration, the invalid-config startup abort names the file and the parse failure, the runtime token refresh runs inside its margin, and the escalation follows bounded re-enroll retries (credential integrity tests for FR-020, config write and parse tests for FR-022, and lifecycle and reconnect tests for FR-023 named in specs/spec-credential-config-integrity.md's traceability). The malformed-frame test set verifies NFR-003's no-panic bound. The public API surface may need test-support exposure; coordinate with the implementing steps.

### Step 16: Verification gates

- **Files:** none (command execution)
- **Satisfies:** [spec-hardening-test-suite -> FR-025 -> both scenarios], [NFR-007]
- **Code references:** `languages/rust.md`
- **Notes:** Run cargo check, cargo clippy --all-targets -- -D warnings, cargo test, and cargo build --release inside daemon/; record each exit code; report the live phone gate as pending per the settled definition of done.

---

## Ordering Rationale

- **Steps 1 to 4:** the SteamOS milestone (doctor, setup and unit, install and pipeline, documentation) maps to /do build step 7.
- **Steps 5 to 11 and step 14:** the transport hardening milestone maps to /do build step 8. The parser lands first because the lifecycle supervisor and dial path consume its outputs. Step 14 (credential and config integrity) runs inside the same build step 8 per the sign-off decision, whose writes were extended to include `daemon/src/auth/**`, so one developer pass owns main.rs, the session lifecycle, and the credential lifecycle together.
- **Steps 12 to 13:** the media milestone maps to /do build step 9.
- **Steps 15 to 16:** tests owned by developer-tester, then the verification gates; both map to /do build steps 10 and 11.

Each step consumes the outputs of its predecessors: the parser feeds the supervisor and dial path; the timing keys feed the handoff tests; the doctor contract feeds its tests.

---

## Notes for Developer

- Reference the `code` skill for Rust conventions before implementing each step.
- Load traceability comments per `code/references/traceability-comment-format.md` and cite the FR id each change satisfies.
- Preserve the pre-existing local modifications in `daemon/src/setup.rs`; do not revert or clobber uncommitted work in the working tree.
- Run the quality gates (check, clippy with warnings denied, test, release build) at milestone completion, not only at the end.
