# spec-hardening-test-suite

## Metadata

| Field | Value |
|---|---|
| **Feature** | Hardening test suite and verification gates |
| **Parent feature** | spec-transport-lifecycle-hardening.md |
| **Sub-features** | None |
| **Requirement refs** | BR-003, UR-007, FR-024, FR-025, NFR-001, NFR-003, NFR-007 |
| **Feature type** | General (Tooling) |
| **Status** | Draft |

Status values: Draft, Review, Approved, Implemented.

## Description

The test and verification feature of the sprint: a black-box suite covering every settled boundary, plus the four cargo gates that define done. It exists so the hardening claims are testable: malformed frames under both format-byte readings, the timing boundaries, sleep/wake convergence, the audio rule, and the doctor contract.

## Triggered by

| Trigger type | Source | Condition |
|---|---|---|
| Manual process | Developer or CI runs the gates | After any implementation change |
| CI | GitHub workflow push or PR | Every build |

## Required data

| Data | Source | Type | Notes |
|---|---|---|---|
| Spec scenarios | The five sibling specs' Scenario blocks | Test inputs and expectations | Each test cites the FR or scenario it traces to |
| Settled boundary values | The plan's recorded decisions | Constants | 10 s dwell, 1 s to 60 s backoff, -60 dBFS, 200 ms, exit 0/1/2 |
| Existing 58 tests | daemon/src inline test modules | Regression baseline | All must keep passing |

## Behavior

### Requirement: Boundary coverage

The suite SHALL contain tests for: malformed and truncated LTV and L2CAP frames under both format-byte readings; malformed SPP frames per the transport spec; the audio-state anchor on short and long advertisements; the dwell boundary at and past 10 s; the backoff edges at 1 s and the 60 s cap; sleep/wake state convergence; adapter power-off and on recovery; the active-audio rule including the silent-tab, game-audio, and communication-class cases; and the doctor exit contract.

#### Scenario: Coverage check

- **GIVEN** the suite as delivered
- **WHEN** each settled boundary is listed against the tests
- **THEN** every boundary has at least one test citing the FR or scenario id it traces to

#### Scenario: Boundary uncovered

- **GIVEN** a settled boundary with no citing test
- **WHEN** the coverage listing runs
- **THEN** the requirement fails acceptance naming the uncovered boundary

#### Scenario: Regression

- **GIVEN** the existing test suite
- **WHEN** the hardening changes land
- **THEN** every existing test still passes

### Requirement: Verification gates define done

The four gates (cargo check, cargo clippy with warnings denied on all targets, cargo test, cargo build --release) SHALL all pass with zero warnings, with the live phone gate reported pending as a separate pre-merge criterion.

#### Scenario: All green

- **GIVEN** the implementation complete
- **WHEN** the gates run
- **THEN** all four exit 0 with zero warnings

#### Scenario: Any failure

- **GIVEN** a gate failing or warning
- **WHEN** the result is observed
- **THEN** the producing step fixes it before the sprint completes, and the live gate is reported pending

## Algorithmic steps

1. Write the black-box tests from the specs' scenarios, citing FR or scenario ids.
2. Run the four gates; record each exit code.
3. Report the live phone gate as pending per the settled definition of done.

## Output / Outcome

| Output | Type | Description |
|---|---|---|
| Test files | Rust integration tests under daemon/tests/ | Cite FR or scenario ids per test |
| Gate results | Exit codes per gate | Recorded in the plan and the final report |
| Live gate status | Reported as pending | Separate pre-merge criterion per decision 001 |

## Error handling

| Error condition | Handling strategy | Outcome |
|---|---|---|
| A gate fails | Route the failure to the producing step's fix path | No silent retry; the failure is recorded |
| A flaky test | Investigate before rerunning | Deterministic tests only; flakes are defects |

## Events emitted

Not applicable: the suite is run manually or by CI.

## Events consumed

Not applicable.

## Dependencies

| Dependency | Type | Required | Notes |
|---|---|---|---|
| cargo, rustc | Build-time | yes | Rust toolchain on the build host |
| Test-only public API surface | Build-time | yes | Parsing and timing functions reachable from integration tests |
| GitHub Actions runners | CI | yes | The ci.yml workflow runs the same gates |

## Traceability

| Requirement | Spec section | Verified by |
|---|---|---|
| FR-024 | Requirement: Boundary coverage | The suite itself; coverage listing against the settled boundaries |
| FR-025 | Requirement: Verification gates define done | The four gate exit codes recorded in the plan |
| UR-007 | Both requirements | Gate results and test report |
| BR-003 | Output / Outcome | Gate record with zero warnings |
| NFR-001 | Dependencies of spec-media-activity-filtering | Detection latency test |
| NFR-003 | Dependencies of spec-transport-lifecycle-hardening | Malformed-frame test set |
| NFR-007 | Requirement: Verification gates define done | clippy gate exit code |
