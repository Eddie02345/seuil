# Seuil SteamOS Hardening Sprint: Business Requirements Document

**Version:** 1.0
**Date:** 2026-11-18
**Author:** [Author]
**Status:** DRAFT

---

### 1. Introduction

**Purpose:** This document states why the seuil hardening sprint exists: the daemon works in the happy path but faults, malformed traffic, service restarts, and the Steam Deck environment break it in ways users cannot diagnose or recover from.

**Project overview:** A four-audit hardening sprint over the seuil daemon (Samsung Continuity / Galaxy Buds Auto Switch for Linux): a `seuil doctor` diagnostic, SteamOS-safe install and service survival, transport and handoff hardening, audio false-positive filtering, and credential and configuration resilience, verified by the cargo gates.

### 2. Stakeholders

| Role | Name/Group | Interest | Influence |
|------|-----------|----------|-----------|
| Repository owner | Maintainer | A daemon that survives real-world fault events and a growing Deck user base | High |
| Desktop user | Linux user with a Samsung phone and Galaxy Buds | Handoffs that happen when real audio plays and never flip back and forth | High |
| Steam Deck user | Deck owner in Gaming Mode or Desktop Mode | Install without a toolchain, service that survives mode switches and suspend | High |
| Packager | Release and CI maintainer | A portable artifact that runs on SteamOS glibc without OpenSSL | Medium |

### 3. Business requirements

| ID | Requirement | Priority | Success criteria |
|----|-------------|----------|-----------------|
| BR-001 | To keep Galaxy Buds auto switch trustworthy on Linux, the business must deliver a daemon that survives suspend/resume, Bluetooth power toggles, service restarts, and malformed BLE traffic without panicking or wedging. | Must | No panic path reachable from malformed input (malformed-frame tests pass); recovery within bounded backoff after restarts |
| BR-002 | To grow the user base onto the Steam Deck, the business must support installing and running seuil on stock SteamOS without disabling the immutable rootfs or installing a compiler toolchain. | Must | Prebuilt install path works from $HOME; the service survives Gaming Mode round trips |
| BR-003 | To make faults diagnosable without log archaeology, the business must ship a one-command diagnostic with stable exit codes and a blocking/advisory split. | Must | `seuil doctor` contract implemented and tested |
| BR-004 | To protect user trust in Samsung account security, the business must preserve credential integrity across writes, restarts, and refresh cycles and never expose key material. | Must | No silent key regeneration; no key material on stdout or in logs |
| BR-005 | To make handoffs deterministic, the business must prevent ping-pong switching and mid-game audio hijacks driven by silent or spurious streams. | Must | 10 s dwell and capped backoff enforced; silent-stream false positives eliminated by the peak-window rule |

### 4. Scope

#### In scope

- Doctor command with the settled exit contract: gives users and support one command that names the broken component.
- SteamOS-safe install: prebuilt path, user-unit survival across session modes, non-fatal optional dependencies.
- Transport hardening: malformed-frame safety, teardown and re-init on suspend and power toggles, dial safety, SPP wiring.
- Handoff timing: configurable dwell and connect backoff.
- Audio filtering: peak-window active-audio rule with capture and communication exclusion.
- Credential, configuration, and setup resilience per the auth audit.
- Tests and the four cargo verification gates.

#### Out of scope

| Excluded item | Reason | Deferred to |
|---------------|--------|-------------|
| Executing the live phone acceptance gate | No phone or Buds attached during this sprint; decision 001 keeps it the pre-merge criterion | Pre-merge live gate |
| OAuth sign-in automation inside Gaming Mode | Samsung sign-in needs a desktop browser; settled as a Desktop Mode activity | Never (by design) |
| AdvertisementMonitor1-based scanning | Current code needs no experimental BlueZ interfaces; a monitor-based scanner is a rework | Future scanner rework |
| musl static release target | Settled on a gnu build with an old glibc baseline | Deferred |
| docs/PROTOCOL_SPEC.md quality overhaul (normative ids, marker vocabulary, remaining internal contradictions) | Recorded as intake findings; the user adopted only the transport-split and audio-anchor corrections this sprint | Separate documentation pass |
| Phone-side protocol changes | The protocol is Samsung's; only the Linux peer changes | Never |

### 5. Constraints

- Samsung's protocol is proprietary and fixed; the Linux peer adapts to it (docs/decisions/001-samsung-continuity-implementation.md).
- SteamOS ships an immutable rootfs: nothing may require `steamos-readonly disable` or a pacman toolchain on the target.
- The install layout stays as documented: binary in `~/.local/bin`, config and credentials in `~/.config/seuil/`, user unit in `~/.config/systemd/user/`.
- Since SteamOS 3.6, `/etc` survives updates only via its migration allowlist; any suggested `/etc` change must carry that caveat.

### 6. Assumptions

- Target SteamOS 3.x with a BlueZ at or above 5.83 and PipeWire running as a user service (audit web citations).
- The user can reach Desktop Mode once for interactive setup and credential enrollment.
- The phone advertises the CoC PSM per advertisement (docs/PROTOCOL_SPEC.md section 1); 128 is this daemon's default constant, not a protocol requirement.

### 7. Success criteria

| ID | Criterion | Measurement | Target |
|----|-----------|-------------|--------|
| SC-001 | All four cargo gates pass | cargo check, clippy with warnings denied, cargo test, release build | Zero warnings, all exit 0 |
| SC-002 | Doctor contract holds | Exit-code and check-set tests | 0 all pass, 1 blocking failure, 2 internal error |
| SC-003 | No panic on malformed input | Malformed-frame test set (LTV, L2CAP, SPP, both format-byte readings) | All pass, no panic |
| SC-004 | Handoff timing honored | Boundary tests for dwell and backoff | 10 s dwell, 1 s doubling to 60 s cap |
| SC-005 | Deck install stays inside $HOME | Path inventory plus install.sh behavior | Every writable path under $HOME; no toolchain use on the prebuilt path |

### 8. Glossary

| Term | Definition |
|------|-----------|
| seuil | This Rust daemon; the name means threshold |
| CoC | L2CAP Connection-Oriented Channel; here the BLE credit-based channel to the phone |
| PSM | Protocol/Service Multiplexer; the CoC's port number, advertised by the phone |
| LTV | Type-length-value record format inside Samsung BLE manufacturer data |
| SPP | Serial Port Profile over RFCOMM; carries Buds opcodes |
| MPRIS | Desktop media-player control interface |
| HFP / A2DP | Bluetooth call profile / audio streaming profile |
| PrepareForSleep | logind D-Bus signal fired around system suspend and resume |
| Gaming Mode / Desktop Mode | SteamOS game session (gamescope) / full desktop session |
| A/B update | SteamOS atomic rootfs update; only /home and allowlisted /etc persist |
| doctor | The `seuil doctor` diagnostic subcommand |

### 9. Revision history

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-11-18 | [Author] | Initial draft from the four audit reports and the settled planning decisions |
