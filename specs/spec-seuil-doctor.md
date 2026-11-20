# spec-seuil-doctor

## Metadata

| Field | Value |
|---|---|
| **Feature** | seuil doctor diagnostic command |
| **Parent feature** | None |
| **Sub-features** | None |
| **Requirement refs** | BR-003, UR-002, UR-007, FR-001, NFR-005 |
| **Feature type** | Functionality |
| **Status** | Draft |

Status values: Draft, Review, Approved, Implemented.

## Description

`seuil doctor` is a read-only diagnostic subcommand that checks every runtime dependency and state the daemon needs, prints one line per check, and exits with a code that scripts and users can branch on. It exists because the four audits showed failures that are silent today: a missing sdptool kills startup, a missing pactl disables audio detection without a message, and absent credentials surface as a generic phone-address error.

## Triggered by

| Trigger type | Source | Condition |
|---|---|---|
| User action | CLI invocation `seuil doctor` | Any time the user suspects the daemon or wants a pre-flight check |
| Manual process | Setup and support flows | After install and after Desktop Mode enrollment, to verify readiness |

## Required data

| Data | Source | Type | Notes |
|---|---|---|---|
| BlueZ D-Bus availability | System bus `org.bluez` | Boolean | Blocking; unreachable bus is itself a reportable state, not an internal error |
| Adapter presence and Powered property | bluer adapter proxy | Boolean | Blocking; names the adapter id when found |
| PipeWire socket | `$XDG_RUNTIME_DIR/pipewire-0` existence | Boolean | Blocking; names the path checked |
| Credentials | `~/.config/seuil/credentials.json` plus `credentials.key` load | Loaded or failed | Blocking; failure names the file and the Desktop Mode setup path |
| Observed CoC PSM | Latest parsed advertisement type 1 record | u16 | Blocking; reported as observed with 128 noted as the default constant |
| bluetoothd experimental interfaces | bluetoothd process arguments or D-Bus property | Boolean | Advisory; current code paths need none |
| Unit state | `systemctl --user is-enabled seuil.service` | Enabled or not | Advisory |
| SteamOS/Deck detection | `/etc/os-release` or kernel cmdline marker | Detected or not | Advisory |

## Preconditions

| Condition | Check | If not met |
|---|---|---|
| Doctor runs as the same user as the daemon | uid and `$HOME` comparison | Advisory line noting the mismatch, not a failure |

## Algorithmic steps

### Requirement 1: Collect environment facts without aborting

The doctor SHALL gather every check input, degrading a missing input to a failed or advisory check rather than aborting.

#### Scenario: All inputs available

- **GIVEN** every check input reachable
- **WHEN** the doctor gathers them
- **THEN** each check reports its input's state and the run proceeds through the blocking and advisory sets

#### Scenario: System bus unreachable

- **GIVEN** no `org.bluez` on the system bus
- **WHEN** the BlueZ check runs
- **THEN** the doctor SHALL print a blocking failure naming the unreachable bus
- **AND** the doctor SHALL continue with the remaining checks

#### Scenario: Probe tool missing

- **GIVEN** a check's helper tool is absent, for example systemctl
- **WHEN** that check runs
- **THEN** the doctor SHALL print an advisory or blocking failure naming the missing tool and continue without aborting

### Requirement 2: Run blocking checks and report one line each

The doctor SHALL run the blocking set (BlueZ reachable, adapter powered, PipeWire socket present, credentials present, CoC PSM observed) and print one pass or fail line per check with the next action on failure.

#### Scenario: All blocking checks pass

- **GIVEN** a healthy system
- **WHEN** the doctor runs
- **THEN** every blocking line reports pass and the advisory set follows

#### Scenario: Credentials absent

- **GIVEN** no credentials store in `~/.config/seuil/`
- **WHEN** the doctor runs
- **THEN** the credentials line reports a blocking failure that names the Desktop Mode setup path (`seuil setup`)
- **AND** the exit code is 1

### Requirement 3: Report the PSM as observed

The doctor SHALL report the PSM from the latest parsed advertisement, treating 128 as the default constant and failing only when the CoC connect fails.

#### Scenario: Observed PSM reported without failing on difference

- **GIVEN** the latest advertisement carries PSM 0x0081 (129)
- **WHEN** the PSM check runs
- **THEN** the line reports the observed 0x0081 and notes the default 128
- **AND** the line does not fail merely because the value differs from the default

#### Scenario: CoC connect fails

- **GIVEN** the observed PSM whose CoC connect fails
- **WHEN** the PSM check runs
- **THEN** the line fails naming the connect failure
- **AND** the exit code is 1

### Requirement 4: Exit with the contract codes

The doctor SHALL exit 0 when every check passes, 1 when any blocking check fails, and 2 only when its own machinery fails.

#### Scenario: All checks pass

- **GIVEN** every blocking and advisory check passing
- **WHEN** the doctor completes
- **THEN** every line reports pass and the exit code is 0

#### Scenario: Advisory-only failures

- **GIVEN** all blocking checks pass and one advisory check fails
- **WHEN** the doctor completes
- **THEN** the exit code is 0 and the advisory line names the failure

#### Scenario: Internal error

- **GIVEN** the doctor's own machinery throws, for example an unrecoverable I/O error in its check runner
- **WHEN** the failure escapes the check guard
- **THEN** the doctor prints an internal-error line naming the failing subsystem and exits 2

## Business rules

| Rule ID | Rule | Traces to | Applied at step | Example |
|---|---|---|---|---|
| RULE-001 | Blocking set: BlueZ reachable, adapter powered, PipeWire socket present, credentials present, CoC PSM observed | FR-001 | Requirement 2 | Missing credentials file blocks with exit 1 |
| RULE-002 | Advisory set: bluetoothd experimental interfaces, unit enabled, SteamOS/Deck detected | FR-001 | Requirement 2 | Unit disabled prints a warning with exit 0 |
| RULE-003 | PSM is reported as observed; 128 is the default constant, not a requirement | FR-001 | Requirement 3 | PSM 0x0080 passes while being reported as observed |
| RULE-004 | Exit 0 all pass, 1 blocking failure, 2 internal error | FR-001 | Requirement 4 | Advisory failure exits 0 |

## Data transformations

| Input | Transformation | Output | Notes |
|---|---|---|---|
| Adapter D-Bus proxy query | Reachability and Powered read | One check line | Errors map to failures, not aborts |
| Credentials load attempt | Load or structured error | One check line | Names the file involved |

## Output / Outcome

| Output | Type | Description |
|---|---|---|
| Check lines on stdout | Text, one line per check | Check name, result, detail, and next action on failure |
| Process exit code | 0, 1, or 2 | The contract in RULE-004 |

## Error handling

| Error condition | Handling strategy | Outcome |
|---|---|---|
| A check's data source is missing | Report the check as failed or advisory with the reason | Other checks still run |
| A probe helper is missing | Report and continue | Line names the missing tool |
| Doctor machinery itself fails | Internal-error line, exit 2 | User sees the failing subsystem |

## Events emitted

Not applicable: a CLI run emits no events.

## Events consumed

Not applicable: the doctor reads state; it does not subscribe.

## Performance considerations

| Concern | Target | Approach |
|---|---|---|
| Total runtime | Under 10 s on a Deck | Each probe carries a timeout; checks run in parallel where independent |

## Traceability

| Requirement | Spec section | Verified by |
|---|---|---|
| FR-001 | Requirements 1 to 4 | Doctor exit-contract tests (FR-024) |
| UR-002 | Output / Outcome | User review of printed lines |
| BR-003 | Business rules RULE-001 to RULE-004 | Exit-code tests |
| NFR-005 | Requirement 4 and Output / Outcome | Output format test |
