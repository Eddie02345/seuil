# spec-credential-config-integrity

## Metadata

| Field | Value |
|---|---|
| **Feature** | Samsung credential, token, and configuration integrity |
| **Parent feature** | spec-transport-lifecycle-hardening.md |
| **Sub-features** | None |
| **Requirement refs** | BR-001, BR-004, UR-005, UR-006, FR-020, FR-021, FR-022, FR-023, NFR-002 |
| **Feature type** | Functionality |
| **Status** | Draft |

Status values: Draft, Review, Approved, Implemented.

## Description

Owns the Samsung account credential store, its key, token refresh, certificate re-enrollment, and the daemon's own configuration files. The auth audit found a missing key is silently regenerated (orphaning the encrypted store), config and unit files are written non-atomically, no runtime token refresh exists, and certificate rotation makes every handshake fail until the user reruns setup.

## Triggered by

| Trigger type | Source | Condition |
|---|---|---|
| System startup | Daemon start | Credentials and config load |
| Schedule | Token expiry margin | A token enters its refresh window |
| Event | Handshake failure | The phone rejects the stored certificate or key |
| Called by feature | Transport spec's CoC manager | Each handshake reloads the store |
| Manual process | `seuil setup` | Enrollment and re-enrollment |

## Required data

| Data | Source | Type | Notes |
|---|---|---|---|
| credentials.json | AES-256-GCM envelope at `~/.config/seuil/credentials.json`, AAD `linux-mcfds-credentials-v1`, version 1 | Encrypted file | Written atomically with a synced parent directory |
| credentials.key | Raw 32-byte AES key at `~/.config/seuil/credentials.key`, mode 0600 | Key file | Missing key is a load failure, never a regeneration |
| config.toml | `~/.config/seuil/config.toml` | Config file | Written atomically; parse failure aborts startup |
| Token expiry | `expires_in` from the service token response | Seconds | Refresh margin 120 s; non-positive values treated as invalid |
| Certificate revision | Cloud enrollment response | Value | Mismatch with the stored device name triggers re-enroll |

## Preconditions

| Condition | Check | If not met |
|---|---|---|
| Key file present, readable, 32 bytes, not a symlink | Stat and length check | Load fails naming the key file; no new key is written |

## Algorithmic steps

### Requirement 1: Load and save credentials atomically

The system SHALL fail credential loading when the key is missing, unreadable, or wrong-length, and save atomically with a unique temp file, a file sync, and a parent-directory sync.

#### Scenario: Key deleted

- **GIVEN** the envelope present and the key file deleted
- **WHEN** credentials load
- **THEN** loading fails naming the key file and no new key is written

#### Scenario: Key unreadable

- **GIVEN** `credentials.key` with permissions or ownership that deny reading
- **WHEN** credentials load
- **THEN** loading fails naming the key file and no new key is written

#### Scenario: Key wrong length

- **GIVEN** `credentials.key` containing a length other than 32 bytes
- **WHEN** credentials load
- **THEN** loading fails naming the length mismatch and no new key is written

#### Scenario: Crash mid-save

- **GIVEN** a save interrupted by crash or power loss
- **WHEN** the daemon next loads
- **THEN** the previous envelope is intact and decryptable

#### Scenario: Stale temp file

- **GIVEN** a leftover temp file from a crashed save
- **WHEN** the next save runs
- **THEN** the save succeeds without manual cleanup

### Requirement 2: Keep key material out of output

The system SHALL keep account keys, tokens, and certificates out of stdout and logs, with debug formatting of credential structures redacting secret fields.

#### Scenario: Auth output

- **GIVEN** a successful authentication or refresh
- **WHEN** output is inspected
- **THEN** no key or token material appears

#### Scenario: Debug print

- **GIVEN** a credential structure formatted with Debug
- **WHEN** output is inspected
- **THEN** secret fields are redacted

#### Scenario: Failed authentication logs no secrets

- **GIVEN** an authentication attempt that fails
- **WHEN** the error is logged
- **THEN** the log line names the failure without any key, token, or private key material

### Requirement 3: Write config and unit atomically with loud failures

The system SHALL write config.toml and the systemd unit atomically, create the config directory owner-only, and abort startup on an invalid config.toml with the parse error.

#### Scenario: Crash during config save

- **GIVEN** an interrupted config write
- **WHEN** the file is next read
- **THEN** the previous content is intact

#### Scenario: Interrupted unit write

- **GIVEN** a systemd unit write interrupted by a crash
- **WHEN** setup next reads the unit file
- **THEN** the previous unit content is intact

#### Scenario: TOML typo

- **GIVEN** a config.toml with a syntax error
- **WHEN** the daemon starts
- **THEN** startup aborts naming the file and the parse failure

#### Scenario: Directory permissions

- **GIVEN** a fresh install
- **WHEN** setup creates the config directory
- **THEN** the directory is 0700

### Requirement 4: Refresh tokens and re-enroll with escalation

The system SHALL refresh expiring tokens at runtime, retry re-enrollment within a bound and escalate visibly when the handshake indicates invalid credentials, and back off pairing failures with growing delays.

#### Scenario: Token refresh

- **GIVEN** a service token whose expiry enters the 120-second refresh margin while the daemon runs
- **WHEN** the refresh path executes
- **THEN** the token is refreshed and persisted without user action
- **AND** a token whose expiry lies outside the margin does not trigger a refresh

#### Scenario: Certificate rotation

- **GIVEN** the phone rejects the stored certificate
- **WHEN** bounded retries exhaust
- **THEN** a clear escalation tells the user to rerun setup

#### Scenario: Session recovery

- **GIVEN** bluetoothd restarted
- **WHEN** the daemon notices the dead session
- **THEN** it re-acquires the adapter with backoff and resumes (with the transport spec's supervisor)

#### Scenario: Pairing failures back off

- **GIVEN** repeated pairing failures, for example a permissions problem
- **WHEN** the retry loop runs
- **THEN** the delay between attempts grows with each failure
- **AND** the failure stays visible in the logs

## Business rules

| Rule ID | Rule | Traces to | Applied at step | Example |
|---|---|---|---|---|
| RULE-001 | A missing key is a failure, never a regeneration | FR-020 | Requirement 1 | Deleted key: load fails, store stays decryptable-by-nothing, no orphan |
| RULE-002 | Saves are atomic and durable (file sync plus parent sync) | FR-020 | Requirement 1 | Power loss keeps the prior envelope |
| RULE-003 | Secrets never reach stdout, logs, or Debug output | FR-021 | Requirement 2 | Auth run prints no account key |
| RULE-004 | Invalid config aborts; defaults are never silently substituted | FR-022 | Requirement 3 | TOML typo names the file and line |
| RULE-005 | Invalid-credential retries are bounded and escalate | FR-023 | Requirement 4 | Rotation ends in a rerun-setup message, not an infinite loop |

## Data transformations

| Input | Transformation | Output | Notes |
|---|---|---|---|
| Credentials struct | Serialize, encrypt (AES-256-GCM, random nonce) | Envelope file | Atomic write path |
| Service token response | Expiry parse with margin | Refresh decision | Non-positive expiry is invalid |
| Stored device name versus hostname | Compare | Re-enroll decision | Warn before any silent identity change |

## Output / Outcome

| Output | Type | Description |
|---|---|---|
| Refreshed credential store | Envelope file | Persisted atomically after every refresh or enroll |
| Escalation messages | Log and user-facing lines | Name the action needed (rerun setup) |

## Error handling

| Error condition | Handling strategy | Outcome |
|---|---|---|
| Key missing or wrong length | Fail the load with a specific error | No silent regeneration; doctor reports it |
| Decrypt failure | Specific error naming corruption or key mismatch | Startup surfaces the real cause, not a missing phone |
| Token refresh failure | Retry within bounds, then warn | Daemon continues on the stored account key until escalation |
| Re-enroll failure | Bounded retries, then escalate | User is told to rerun setup |
| Config parse failure | Abort startup with the error | No silent default substitution |

## Events emitted

| Event name | Payload | Consumer(s) | When emitted |
|---|---|---|---|
| credentials.refreshed | None | Transport spec's CoC manager | After a successful runtime refresh |
| credentials.escalation | Reason | Logs, doctor | After bounded re-enroll retries fail |

## Events consumed

| Event name | Producer | Payload used | Handling |
|---|---|---|---|
| handshake.rejected | Transport spec's CoC manager | Failure kind | Starts the bounded re-enroll path |

## Performance considerations

| Concern | Target | Approach |
|---|---|---|
| Load cost at startup and per handshake | Under 10 ms typical | One read plus one AES-GCM decrypt; no network on the load path |

## Traceability

| Requirement | Spec section | Verified by |
|---|---|---|
| FR-020 | Requirement 1 | Credential integrity tests |
| FR-021 | Requirement 2 | Output inspection test; NFR-002 |
| FR-022 | Requirement 3 | Config write and parse tests |
| FR-023 | Requirement 4 | Lifecycle and reconnect tests; NFR-004 |
| UR-006 | Business rules RULE-001 to RULE-003 | Acceptance: no secret output, no silent replacement |
| BR-004 | All requirements | Credential policy review |
| NFR-002 | Requirement 2 and business rule RULE-003 | Output tests |
