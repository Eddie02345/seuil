# spec-steamos-deck-support

## Metadata

| Field | Value |
|---|---|
| **Feature** | SteamOS / Steam Deck install and service support |
| **Parent feature** | None |
| **Sub-features** | None |
| **Requirement refs** | BR-002, UR-001, UR-002, FR-002, FR-003, FR-004, FR-005, FR-006, FR-007, NFR-006 |
| **Feature type** | General (Infrastructure and Tooling) |
| **Status** | Draft |

Status values: Draft, Review, Approved, Implemented.

## Description

Everything seuil needs to install and run on a stock Steam Deck without touching the immutable rootfs: a prebuilt install path, a user unit that survives Gaming Mode round trips, optional-dependency degradation instead of startup aborts, the printed BlueZ experimental drop-in with a flag-gated write, the portable release artifact, and the documentation that ties it together.

## Triggered by

| Trigger type | Source | Condition |
|---|---|---|
| Manual process | User runs `install.sh --from-release` | Installing on a Deck or any machine without a toolchain |
| Deployment | User manager starts `seuil.service` | Login on SteamOS in either session mode |
| Deployment | Release workflow publishes a tag | Producing the portable artifact |
| Configuration change | User runs `seuil setup` | Installing the unit and printing the optional drop-in |

## Required data

| Data | Source | Type | Notes |
|---|---|---|---|
| Release artifact URL | GitHub releases for the current version | tar.gz download | x86_64-unknown-linux-gnu build from the baseline container |
| Install target | `$HOME/.local/bin` | Directory | Created when missing; never outside `$HOME` |
| Unit text | setup source | systemd unit | No `PartOf=graphical-session.target`; user-scope ordering only |
| Optional tools | PATH probes | sdptool, pactl, playerctl | Absence degrades, never aborts |
| BlueZ drop-in content | setup source | override.conf text | Printed with the exact sudo install command and the `/etc` allowlist caveat |

## Behavior

### Requirement: Prebuilt install path

The installer SHALL provide `--from-release`, which downloads the release artifact into `~/.local/bin` and runs no compiler or package manager.

#### Scenario: Fresh Deck

- **GIVEN** stock SteamOS with network access and no Rust toolchain
- **WHEN** the user runs the prebuilt path
- **THEN** the binary lands executable at `~/.local/bin/seuil` and nothing outside `$HOME` changed

#### Scenario: Download or verification failure

- **GIVEN** the artifact is unreachable or fails verification
- **WHEN** the install runs
- **THEN** the installer exits non-zero with a clear message and leaves no partial executable

### Requirement: Unit survives session-mode changes

The user unit SHALL keep the daemon started across a Gaming Mode to Desktop Mode switch, start on a pure Gaming Mode boot, and wait for Bluetooth readiness with backoff instead of exiting when BlueZ is not yet up.

#### Scenario: Mode round trip

- **GIVEN** the unit active in Gaming Mode
- **WHEN** the session switches to Desktop Mode and back
- **THEN** the unit stays active and the daemon is functional after the switch

#### Scenario: Bluetooth not ready at login

- **GIVEN** the unit starts before bluetoothd is ready
- **WHEN** the adapter is not yet powered
- **THEN** the daemon waits with backoff and proceeds once BlueZ is reachable

### Requirement: Optional dependencies degrade, never abort

A missing optional tool SHALL produce a persistent warning and disable only the matching feature, with a failing invocation of a present tool distinguished from a missing service record.

#### Scenario: sdptool missing on SteamOS

- **GIVEN** SteamOS bluez-utils without sdptool
- **WHEN** the daemon starts
- **THEN** startup completes with a warning naming sdptool, and doctor reports the degraded SDP path

#### Scenario: sdptool exits non-zero

- **GIVEN** sdptool present but the local SDP query fails for a missing compatibility flag
- **WHEN** the SDP step runs
- **THEN** the warning names the compatibility requirement, not a missing service record

#### Scenario: pactl or playerctl missing

- **GIVEN** either probe tool absent
- **WHEN** the daemon runs and doctor is invoked
- **THEN** both name the degraded audio detection source

### Requirement: BlueZ drop-in printed, written only behind a flag

Setup SHALL print the optional `bluetooth.service.d` override content and the exact privileged install command, write `/etc` only behind an explicit flag, and include the SteamOS `/etc` allowlist caveat.

#### Scenario: Default setup run

- **GIVEN** setup without the flag
- **WHEN** the BlueZ step executes
- **THEN** the override content and sudo command print, nothing is written under `/etc`, and the allowlist caveat appears

#### Scenario: Flag run

- **GIVEN** the explicit flag passed
- **WHEN** setup runs
- **THEN** the printed privileged command executes and doctor then reports the experimental flag state

#### Scenario: Privileged write fails

- **GIVEN** the explicit flag passed and the privileged command fails, for example sudo denied
- **WHEN** setup handles the failure
- **THEN** the error names the failed command and nothing was written under `/etc`
- **AND** doctor reports the drop-in as absent

### Requirement: Portable release artifact

The release pipeline SHALL produce an x86_64 gnu artifact verified against the glibc 2.31 baseline with no OpenSSL linkage.

#### Scenario: Verification passes

- **GIVEN** the artifact built in the baseline container
- **WHEN** the linkage check runs
- **THEN** only basic system libraries compatible with 2.31 are listed and the job succeeds

#### Scenario: Verification fails

- **GIVEN** a dependency pulls a newer library
- **WHEN** the linkage check runs
- **THEN** the release job fails instead of shipping

### Requirement: Documentation and decision record

The README and a numbered decision record under `docs/decisions/` SHALL document the Steam Deck path and the SteamOS install architecture.

#### Scenario: Reader follows the README

- **GIVEN** a fresh Deck and the README
- **WHEN** the reader follows the Steam Deck section
- **THEN** they reach a doctor-verified service without leaving `$HOME` and know setup belongs in Desktop Mode

#### Scenario: Decision record content

- **GIVEN** the sprint complete
- **WHEN** a reader opens the numbered decision record under `docs/decisions/`
- **THEN** it states the settled install layout, the drop-in policy with the flag-gated write, and the portable build-target choice, each with its rationale

#### Scenario: Documentation missing

- **GIVEN** the sprint's changes landed
- **WHEN** the README's Steam Deck section or the numbered decision record under `docs/decisions/` is absent
- **THEN** the requirement fails acceptance with the missing artifact named

## Algorithmic steps

1. Build the portable artifact in the baseline container and verify linkage.
2. Install via the prebuilt path or the existing source path.
3. Run setup once in Desktop Mode: config, unit, enable, start, and the printed drop-in.
4. Verify with `seuil doctor`; fix blocking items; note advisory ones.

## Output / Outcome

| Output | Type | Description |
|---|---|---|
| Installed binary | File under `$HOME` | Executable at `~/.local/bin/seuil` |
| User unit | `~/.config/systemd/user/seuil.service` | Survives mode switches |
| Printed drop-in instructions | Text | Exact sudo command plus allowlist caveat |
| README section and decision record | Documentation | The Deck path and its rationale |

## Error handling

| Error condition | Handling strategy | Outcome |
|---|---|---|
| Artifact download fails | Abort with a clear message | No partial binary |
| Unit enable or start fails | Surface the systemctl output | User sees the failing command |
| Optional tool missing | Warn and degrade the feature | Daemon runs; doctor reports it |

## Events emitted

Not applicable: installation and setup are manual processes.

## Events consumed

Not applicable.

## Dependencies

| Dependency | Type | Required | Notes |
|---|---|---|---|
| systemd user manager | Runtime | yes | Present on SteamOS for the deck user |
| BlueZ 5.48 or newer | Runtime | yes | LEAdvertisingManager1 stable; no `-E` needed for current paths |
| PipeWire user service | Runtime | yes | Socket under `$XDG_RUNTIME_DIR` |
| sdptool (bluez-deprecated-tools) | Runtime | no | Degrades with a warning; see FR-004 |
| pactl, playerctl | Runtime | no | Audio detection degrades without them |
| Debian 11 container image | Build-time | yes | glibc 2.31 baseline for the portable artifact |
| rustls | Build-time | yes | No OpenSSL linkage in the artifact |

## Traceability

| Requirement | Spec section | Verified by |
|---|---|---|
| FR-002 | Requirement: Prebuilt install path | Install path test plus path inventory |
| FR-003 | Requirement: Unit survives session-mode changes | Unit text review plus mode-switch behavior |
| FR-004 | Requirement: Optional dependencies degrade, never abort | Dependency-degradation tests |
| FR-005 | Requirement: BlueZ drop-in printed, written only behind a flag | Setup output review plus flag-gate test |
| FR-006 | Requirement: Portable release artifact | Release workflow linkage check |
| FR-007 | Requirement: Documentation and decision record | README review plus decision record existence |
| UR-001 | All requirements | Acceptance walkthrough on SteamOS |
| BR-002 | All requirements | Path inventory: every writable path under `$HOME` |
| NFR-006 | Dependencies and Requirement: Portable release artifact | Path inventory plus CI linkage check |
