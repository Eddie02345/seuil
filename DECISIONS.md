# Decisions

Append-only decision log for /do plans. Architecture decisions for the codebase itself also get a numbered record under `docs/decisions/`.

## 2026-11-18: Doctor command contract

Decision: `seuil doctor` reports the PSM observed in the advertisement Ctx record and keeps 128 as the default constant; it fails only when the CoC connect fails. Exit 0 all pass, 1 any blocking failure, 2 internal error; one line per check. Blocking: BlueZ reachable on D-Bus, adapter powered, PipeWire socket present, credentials present, CoC PSM observed. Advisory: bluetoothd experimental interfaces, user unit enabled, SteamOS/Deck detected.
Plan: .agent/main-plan/plan-seuil-steamos-hardening-20261118-2109.md

## 2026-11-18: Protocol model for hardening

Decision: Phone-directed auto switch commands travel over the BLE CoC; Buds opcodes (SET_SEAMLESS_CONNECTION and acknowledgements) travel over SPP. The hardened parser accepts both the offset-2 and offset-3 format-byte readings and rejects only when both fail. The daemon's implemented NS anchoring formula is authoritative for audio state. docs/PROTOCOL_SPEC.md section 1 wording and the section 8 diagram are corrected to match.
Plan: .agent/main-plan/plan-seuil-steamos-hardening-20261118-2109.md

## 2026-11-18: Handoff timing defaults

Decision: A 10 second minimum dwell between handoff requests and an L2CAP CoC connect backoff of 1 second doubling to a 60 second cap, both keys in config.toml with those defaults, plus one boundary test each.
Plan: .agent/main-plan/plan-seuil-steamos-hardening-20261118-2109.md

## 2026-11-18: Active audio rule

Decision: A stream counts as active when PipeWire reports it RUNNING and its peak stays above -60 dBFS over a 200 ms window. Capture-side and communication-class streams are excluded. Thresholds are configurable. An active HFP call blocks media-reason handoffs while call-reason switching stays allowed during HFP.
Plan: .agent/main-plan/plan-seuil-steamos-hardening-20261118-2109.md

## 2026-11-18: SteamOS install layout and packaging

Decision: Existing paths are kept: binary in ~/.local/bin, config and credentials in ~/.config/seuil/, user unit in ~/.config/systemd/user/. install.sh gains a --from-release prebuilt path that skips toolchain checks. The portable release target is x86_64-unknown-linux-gnu built inside a Debian 11 container on the glibc 2.31 baseline, keeping rustls so no OpenSSL links, verified with ldd. Interactive setup stays a Desktop Mode activity; doctor reports missing credentials in Gaming Mode.
Plan: .agent/main-plan/plan-seuil-steamos-hardening-20261118-2109.md

## 2026-11-18: BlueZ drop-in policy

Decision: Setup prints the bluetooth.service.d override.conf content and the exact sudo install command. /etc is written only behind an explicit setup flag. Doctor only reports whether bluetoothd runs with experimental interfaces.
Plan: .agent/main-plan/plan-seuil-steamos-hardening-20261118-2109.md

## 2026-11-18: Sprint definition of done

Decision: cargo check, cargo clippy --all-targets -- -D warnings, cargo test, and cargo build --release must pass with zero warnings. The live phone acceptance gate from docs/decisions/001 stays a separate pre-merge criterion, reported pending when no hardware is attached.
Plan: .agent/main-plan/plan-seuil-steamos-hardening-20261118-2109.md

## 2026-11-18: Credential hardening joins the transport milestone

Decision: Task-plan step 14 (credential and config integrity) is implemented inside build step 8, adding daemon/src/auth/** to that step's writes; one developer pass owns main.rs, the session lifecycle, and the credential lifecycle together.
Plan: .agent/main-plan/plan-seuil-steamos-hardening-20261118-2109.md

## 2026-11-18: Hybrid review gates under the dispatch ceiling

Decision: Planning-gate reviewer passes and build milestones dispatch when the per-message dispatch ceiling allows (reset by the user's messages); code review gates run inline in the orchestrator with file:line findings recorded per gate, keeping the producing agent separate from the reviewer.
Plan: .agent/main-plan/plan-seuil-steamos-hardening-20261118-2109.md
