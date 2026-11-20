# spec-media-activity-filtering

## Metadata

| Field | Value |
|---|---|
| **Feature** | Media activity filtering and handoff media policy |
| **Parent feature** | spec-transport-lifecycle-hardening.md |
| **Sub-features** | None |
| **Requirement refs** | BR-005, UR-003, UR-004, FR-016, FR-017, FR-018, FR-019, NFR-001 |
| **Feature type** | Functionality |
| **Status** | Draft |

Status values: Draft, Review, Approved, Implemented.

## Description

Decides when local audio counts as activity worth asking the Buds for, and how media is paused, released, and pulled back during handoffs. The audio audit found detection is two text-scraping probes with no peak measurement, so silent tabs, muted players, and notification blips all trigger switches, and probe failures fabricate stop/start edges.

## Triggered by

| Trigger type | Source | Condition |
|---|---|---|
| Schedule | Media monitor tick | Every poll interval, evaluating stream state and peaks |
| Event | PipeWire or MPRIS state change | A stream starts, stops, or changes class |
| Called by feature | Handoff state machine | A release or grant needs media action |

## Required data

| Data | Source | Type | Notes |
|---|---|---|---|
| Stream state | PipeWire (via its native interface or bounded probes) | RUNNING or not | Per sink-input stream |
| Stream peak | PipeWire peak measurement | dBFS | Sampled inside the activity window |
| Stream class | PipeWire media.class metadata | Playback, capture, communication | Capture and communication are excluded from media activity |
| MPRIS playback status | Session bus MPRIS players | Playing or not | Secondary signal, never sufficient alone for a trigger |
| Threshold and window | config.toml | dBFS and milliseconds | Defaults -60 dBFS and 200 ms |

## Preconditions

| Condition | Check | If not met |
|---|---|---|
| At least one probe source healthy | Probe succeeds within its timeout | Hold last known state; warn persistently; no edges |

## Algorithmic steps

### Requirement 1: Classify stream activity

The media monitor SHALL classify a stream as active only while it is RUNNING with its peak above the configured threshold across the configured window, excluding capture-side and communication-class streams.

#### Scenario: Silent tab

- **GIVEN** a RUNNING stream whose peak stays below -60 dBFS across the 200 ms window
- **WHEN** the monitor evaluates it
- **THEN** the stream SHALL NOT be active and no handoff request fires

#### Scenario: Game audio

- **GIVEN** a RUNNING stream above the threshold across the window
- **WHEN** the monitor evaluates it
- **THEN** the stream SHALL be active within the NFR-001 latency bound
- **AND** exactly one media-reason request fires

#### Scenario: Voice chat

- **GIVEN** a communication-class or capture-side stream
- **WHEN** the monitor evaluates it
- **THEN** the stream SHALL NOT count as media activity

#### Scenario: Custom thresholds

- **GIVEN** config.toml sets a different threshold or window
- **WHEN** the monitor runs
- **THEN** the configured values SHALL be used

### Requirement 2: Apply call policy

The monitor SHALL block media-reason handoffs while an HFP call is active, keep call-reason switching available, and scope the call guard to call-reason responses.

#### Scenario: Media during a call

- **GIVEN** an active HFP call
- **WHEN** local media starts
- **THEN** the media-reason handoff SHALL be suppressed

#### Scenario: Call-reason during HFP

- **GIVEN** an active HFP call
- **WHEN** a call-reason switch request arrives
- **THEN** it SHALL proceed

#### Scenario: Lost call response

- **GIVEN** a call-reason response that never arrives
- **WHEN** media triggers later
- **THEN** media handoffs SHALL NOT be blocked by a blanket timed lock

### Requirement 3: Hold state through probe failures

The monitor SHALL hold the last known activity state on a failed probe or unreachable service, bound every probe with a timeout, and run under supervision so a dead monitor is restarted and logged.

#### Scenario: Healthy evaluation

- **GIVEN** probes succeeding within their timeouts
- **WHEN** a tick evaluates stream state and peaks
- **THEN** the activity state updates from fresh data

#### Scenario: Probe tool absent

- **GIVEN** the probe tool missing
- **WHEN** a tick runs
- **THEN** one persistent warning is logged, the last known state is held, and no stop/start edge pair is emitted

#### Scenario: Probe hangs

- **GIVEN** a probe that never returns
- **WHEN** its timeout expires
- **THEN** the tick completes and later ticks continue

#### Scenario: Service unreachable

- **GIVEN** the PipeWire or MPRIS service unreachable
- **WHEN** the monitor evaluates
- **THEN** the last known activity state is held with a persistent warning
- **AND** no stop/start edge pair is emitted

#### Scenario: PipeWire restart recovery

- **GIVEN** the PipeWire daemon restarting while the daemon runs
- **WHEN** the monitor reconnects after the restart
- **THEN** activity evaluation resumes without a fabricated edge pair

#### Scenario: Monitor death

- **GIVEN** the monitor task exits or panics
- **WHEN** the supervisor notices
- **THEN** the task is restarted and an error is logged

### Requirement 4: Order release and pull correctly

The daemon SHALL verify the pause succeeded and complete profile teardown before answering a release, retry the A2DP connect on a grant, and refrain from pulling A2DP on a call-reason grant.

#### Scenario: Pause failure

- **GIVEN** MPRIS pause fails during a release
- **WHEN** the release completes
- **THEN** the reply SHALL reflect the failure instead of claiming success

#### Scenario: Teardown before reply

- **GIVEN** A2DP and HFP links up during a release
- **WHEN** the daemon answers the phone
- **THEN** the disconnects have completed or their failure is reported in the result path

#### Scenario: Slow A2DP connect

- **GIVEN** a granted media switch whose first connect fails or is slow
- **WHEN** the pull retries
- **THEN** bounded retries occur before a warning

#### Scenario: Call grant

- **GIVEN** a call-reason grant
- **WHEN** it is processed
- **THEN** no A2DP pull is initiated

## Business rules

| Rule ID | Rule | Traces to | Applied at step | Example |
|---|---|---|---|---|
| RULE-001 | Active means RUNNING plus peak above -60 dBFS sustained over 200 ms | FR-016 | Requirement 1 | Silent tab fails the window check |
| RULE-002 | Capture-side and communication-class streams never count as media | FR-016 | Requirement 1 | Voice chat is excluded |
| RULE-003 | A failed probe holds state; it never fabricates an edge | FR-018 | Requirement 3 | pactl absent: no stop/start pair |
| RULE-004 | HFP active blocks media-reason only; call-reason proceeds | FR-017 | Requirement 2 | Media suppressed during a call |
| RULE-005 | The reply to the phone follows verified pause and teardown | FR-019 | Requirement 4 | Failed pause answers failure |

## Data transformations

| Input | Transformation | Output | Notes |
|---|---|---|---|
| Stream states and peaks | Windowed threshold evaluation per stream | Activity boolean per stream | Communication and capture excluded first |
| Activity booleans | OR over media streams | Media-active signal | Drives the handoff trigger |
| Media-active edges | Dwell gate (transport spec) | Handoff request or suppression | Timing owned by the transport spec |

## Output / Outcome

| Output | Type | Description |
|---|---|---|
| Media-active signal | Internal state | Consumed by the handoff state machine |
| Release replies | Protocol response | Result reflects verified pause and teardown |
| Persistent warnings | Log lines | Probe absence, monitor restarts |

## Error handling

| Error condition | Handling strategy | Outcome |
|---|---|---|
| Probe absent or failing | Hold state, warn persistently | No fabricated edges |
| Probe hang | Timeout per probe | Tick completes |
| Monitor task death | Supervised restart | Error logged; detection resumes |
| Pause failure during release | Report failure in the reply | Phone does not believe playback stopped |

## Events emitted

| Event name | Payload | Consumer(s) | When emitted |
|---|---|---|---|
| media.active | Stream summary | Handoff state machine | A stream crosses into activity |
| media.idle | None | Handoff state machine | No active stream remains |

## Events consumed

| Event name | Producer | Payload used | Handling |
|---|---|---|---|
| lifecycle.sleep / lifecycle.wake | Transport spec's lifecycle supervisor | Epoch | Suppress evaluation during teardown; resume cleanly |

## Performance considerations

| Concern | Target | Approach |
|---|---|---|
| Detection latency | Within 1 s of a stream change at defaults (NFR-001) | Peak sampling inside the 200 ms window; no long-blocking probes |

## Traceability

| Requirement | Spec section | Verified by |
|---|---|---|
| FR-016 | Requirement 1 | Audio filter rule tests (FR-024) |
| FR-017 | Requirement 2 | Call-policy tests |
| FR-018 | Requirement 3 | Probe-failure tests |
| FR-019 | Requirement 4 | Release and pull ordering tests |
| NFR-001 | Performance considerations | Detection latency test with a synthetic stream |
| BR-005 | Business rules RULE-001 to RULE-005 | Acceptance: silent tabs and calls behave per the rules |
