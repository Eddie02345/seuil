# Seuil SteamOS Hardening Sprint: User Requirements Document

**Version:** 1.0
**Date:** 2026-11-18
**Author:** [Author]
**Status:** DRAFT

---

### 1. Introduction

**Purpose:** This document captures what each user of seuil needs from the hardening sprint, derived from the four audits and the settled planning decisions.

**Relationship to BRD:** This document derives from BRD-seuil-steamos-hardening.md. Every user requirement traces to at least one business requirement.

### 2. Stakeholder map

| Stakeholder | Role | Goals | Pain points | Priority |
|-------------|------|-------|-------------|----------|
| Steam Deck user | Installs and runs seuil on SteamOS | Prebuilt install inside $HOME; service alive across mode switches and suspend; one command to diagnose | No toolchain on Deck; unit stops after a Gaming Mode round trip; sdptool missing kills startup | High |
| Desktop user | Day-to-day handoffs between phone and Linux | Buds arrive when real audio starts and never ping-pong | Silent tabs and notification blips steal the Buds; probe failures flap the state | High |
| Gamer in an active session | Mid-game audio continuity | The Buds stay put during gameplay; voice chat is treated as a call, not media | Any RUNNING stream triggers a switch today | High |
| Maintainer | Runs the verification suite and reads reports | Green gates with zero warnings; tests that encode the settled boundaries | Manual verification only; live gate needs hardware | Medium |

### 3. User requirements

| ID | Requirement | Stakeholder | Traces to | Priority |
|----|-------------|-------------|-----------|----------|
| UR-001 | The Steam Deck user shall be able to install seuil from a prebuilt release artifact into their home directory without a compiler toolchain and have the service start and stay started across Gaming Mode and Desktop Mode switches. | Deck user | BR-002 | Must |
| UR-002 | The user shall be able to run one diagnostic command that reports each runtime dependency and service state, separates blocking from advisory problems, and states what to do next, including that first-run setup belongs in Desktop Mode. | Deck user, desktop user | BR-003 | Must |
| UR-003 | The desktop user shall experience handoffs that do not flip rapidly between the phone and Linux and never lose the media link mid-handoff. | Desktop user | BR-001, BR-005 | Must |
| UR-004 | The gamer shall have the Buds stay with the current host unless real, audible media or game audio is playing; silent tabs, muted players, UI sounds, and voice-chat streams shall not trigger a media handoff, and an active call shall be honored as a call. | Gamer, desktop user | BR-005 | Must |
| UR-005 | The user shall have a daemon that recovers by itself after suspend/resume, Bluetooth power toggles, and bluetoothd or PipeWire restarts, without a wedged or half-dead state. | Desktop user, deck user | BR-001 | Must |
| UR-006 | The user shall trust that Samsung account credentials never appear in terminal output or logs and are never silently replaced after a partial failure. | All users | BR-004 | Must |
| UR-007 | The maintainer shall be able to run the full verification suite and receive a definitive pass or fail with zero warnings, plus tests that encode the settled timing and parsing boundaries. | Maintainer | BR-003 | Must |

### 4. Use case summaries

#### UC-001: Install seuil on a fresh Steam Deck

- **Primary actor:** Deck user
- **Precondition:** SteamOS 3.x, Desktop Mode available, network access
- **Success guarantee:** Binary at `~/.local/bin/seuil`, user unit enabled, doctor exits 0 after Desktop Mode setup
- **Main scenario:** Download via the prebuilt install path; run setup once in Desktop Mode; verify with doctor; reboot into Gaming Mode and confirm the service is active
- **Key extensions:** sdptool absent (startup continues, doctor reports the degradation); credentials absent (doctor fails with the Desktop Mode setup instruction)

#### UC-002: Diagnose a broken setup

- **Primary actor:** Any user
- **Precondition:** seuil installed or partially installed
- **Success guarantee:** One command names the failing component and the next action
- **Main scenario:** Run `seuil doctor`; read one line per check; fix the blocking item; rerun until exit 0
- **Key extensions:** Internal error (exit 2, names the failing subsystem); advisory-only failures (exit 0 with warnings)

#### UC-003: Keep the Buds during an active game

- **Primary actor:** Gamer
- **Precondition:** Buds connected to the Deck, game audio playing
- **Success guarantee:** No handoff request fires for silent or system sounds; a real game-audio handoff completes; an HFP voice call is honored as a call
- **Main scenario:** Launch a game; audio crosses the peak threshold; the Buds switch exactly once; suspend and resume; the Buds reconnect without duplicates
- **Key extensions:** Voice chat active (call handling, not media); transient probe failure (state held, no flap)

#### UC-004: Survive a suspend/resume cycle

- **Primary actor:** Deck or desktop user
- **Precondition:** Daemon running with an active CoC and advertisement
- **Success guarantee:** After wake, exactly one advertisement and one scan session exist, the channel map is consistent, and a redial happens within backoff bounds
- **Main scenario:** Close the lid; open it; observe teardown then clean re-init in the logs; confirm the phone sees the advertisement again
- **Key extensions:** Rapid sleep/wake flapping (state converges, no duplicates); adapter powered off and on (same outcome)

### 5. Scope

#### In scope (user-facing capabilities)

- One-command diagnostics with stable exit codes.
- Prebuilt installation for SteamOS and any Linux with glibc 2.31 or newer.
- Deterministic, audio-triggered handoffs with call awareness.
- Self-recovery after suspend, power toggles, and service restarts.

#### Out of scope (user-facing exclusions)

| Excluded item | Reason | Deferred to |
|---------------|--------|-------------|
| Interactive Samsung sign-in inside Gaming Mode | The OAuth callback needs a desktop browser and MIME registration (decision 002) | Never (by design) |
| Building from source on the Deck | The immutable rootfs has no toolchain and wipes pacman installs on update | Prebuilt path covers it |

### 6. Assumptions

- Users can reach Desktop Mode once for setup and enrollment.
- The phone runs the Samsung Continuity service and advertises the CoC PSM.
- SteamOS keeps `/home` across A/B updates and runs PipeWire as a user service.

### 7. Open questions

- None. The planning rounds settled every open point; the decisions are recorded in `DECISIONS.md` at the repository root.

### 8. Glossary

| Term | Definition |
|------|-----------|
| doctor | The `seuil doctor` diagnostic subcommand |
| dwell | Minimum time between handoff requests; settled at 10 s, configurable |
| backoff | CoC connect retry delay doubling from 1 s to a 60 s cap |
| peak-window rule | A stream is active when RUNNING and its peak stays above -60 dBFS over 200 ms |
| blocking check | A doctor check whose failure exits 1 |
| advisory check | A doctor check whose failure is reported but does not block |

### 9. Revision history

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-11-18 | [Author] | Initial draft |
