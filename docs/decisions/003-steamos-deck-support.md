# Decision 003: SteamOS and Steam Deck Support

## Status
Accepted (2026-11-19)

## Context
SteamOS 3 runs on an immutable root filesystem and replaces it on every OS
update. The Deck boots either into Gaming Mode (gamescope) or Desktop Mode
(KDE Plasma), and users switch between the two at runtime. The first Seuil
release assumed a writable `/` and a desktop session:

- the user unit carried `PartOf=graphical-session.target`, so a mode switch
  could stop the daemon for the rest of the session;
- the unit ordered `After=bluetooth.target`, which a user unit cannot use
  because it names a system unit;
- a missing `sdptool` aborted startup, and SteamOS bluez-utils ships no
  `sdptool`;
- building on the Deck needs the read-only root disabled, and an update wipes
  both the toolchain and the build;
- installers assumed a Rust toolchain on the target machine.

The sprint settles the install layout, the BlueZ drop-in policy, and the build
target so a stock Deck runs Seuil without touching the immutable root.

## Decision

### Install layout
All user-installed state lives under `$HOME`:

| Path | Contents |
|---|---|
| `~/.local/bin/seuil` | binary |
| `~/.config/seuil/config.toml` | phone and Buds addresses |
| `~/.config/seuil/credentials.json`, `credentials.key` | encrypted Samsung enrollment |
| `~/.config/seuil/bluetooth-override.conf` | printed BlueZ drop-in content, kept for later install |
| `~/.config/systemd/user/seuil.service` | user unit |

Setup creates `~/.config/seuil` with mode 0700 and writes `config.toml` and the
unit through a same-directory temporary file plus `rename`, so an interrupted
write leaves the previous content intact. `/etc` is outside this layout and is
covered by the drop-in policy below.

### User unit
The unit orders only against user-scope targets:

```ini
[Unit]
After=pipewire.service
Wants=pipewire.service
```

It carries no `PartOf=graphical-session.target` and no `After=bluetooth.target`.
`WantedBy=default.target` starts it on a pure Gaming Mode boot. Setup enables
the unit and then restarts it, so a re-run applies new phone and Buds addresses.

### BlueZ drop-in policy
The optional `bluetooth.service.d` override starts bluetoothd with the
experimental interfaces. Setup resolves the bluetoothd executable at run time
(`/usr/lib/bluetooth/bluetoothd` on SteamOS and Arch,
`/usr/libexec/bluetooth/bluetoothd` on the Debian family and Fedora) and builds
the drop-in from the resolved path, so the printed `ExecStart` never names a
binary from another distribution. When no candidate resolves, setup says so and
`--install-bluez-dropin` refuses rather than install a drop-in whose `ExecStart`
points at a nonexistent binary. Setup always prints the content and the exact
privileged command, and writes the content under `~/.config/seuil/`. It writes
under `/etc` only when `seuil setup --install-bluez-dropin` is passed.

```ini
[Service]
ExecStart=
ExecStart=<resolved bluetoothd path> -E
```

SteamOS 3.6 and newer migrates `/etc` by allowlist only. The printed text and
this record carry the caveat: add an entry such as
`systemd/system/bluetooth.service.d/override.conf` to
`/etc/atomic-update.conf.d/` (for example
`/etc/atomic-update.conf.d/seuil-bluez.conf`), or the override is dropped on the
next OS update.

### Portable build target
The release artifact is `x86_64-unknown-linux-gnu`, built inside a `debian:11`
container (glibc 2.31) with the rustls TLS stack. The release job runs an `ldd`
linkage check that fails on any library outside a basic glibc 2.31-era
allowlist, which excludes `libssl` and `libcrypto`. The asset name is stable
(`seuil-x86_64-unknown-linux-gnu.tar.gz`) and ships beside a `.sha256` file.

`install.sh --from-release` downloads that asset, verifies the checksum, and
installs it at `~/.local/bin/seuil`. It calls no compiler and no package
manager. The source path keeps its dependency checks, but `sdptool`, `pactl`,
and `playerctl` moved to optional: their absence degrades one feature and does
not fail the install.

### Optional dependencies and the doctor
Missing `sdptool` is non-fatal at setup and at daemon startup. Startup logs a
warning naming the tool and continues; the SDP-dependent check is skipped.
Missing `pactl` or `playerctl` degrades audio activity detection, and setup and
`seuil doctor` both name the degraded source.

`seuil doctor` is read-only and prints one line per check:

- Blocking: BlueZ reachable on the system bus, adapter powered, PipeWire socket
  present, credentials present, and a CoC PSM observed from the phone's
  advertisement. Exit 1 when any blocking check fails.
- Advisory: bluetoothd experimental interfaces, user unit enabled, SteamOS/Deck
  detected. Advisory failures never change the exit code.
- Exit 0 when every blocking check passes, 1 on a blocking failure, 2 when the
  check runner itself fails.

The PSM check reports the observation (for example `0x0081`) and names 128 as
the default constant. It never asserts 128, and it fails only when the CoC
connect fails. Every probe is timeout-bounded, and a missing tool becomes a
line rather than an abort.

## Rationale

### Why a user unit under `$HOME`?
SteamOS does not persist changes to `/`, and a system unit would need a writable
`/etc/systemd/system` and root on every install. A user unit starts with the
user manager in both session modes, needs no root, and keeps every persistent
path inside `$HOME`.

### Why remove `PartOf` and the system-target ordering?
A user unit cannot depend on `bluetooth.target`; systemd rejects or ignores
system-unit ordering from the user manager. `PartOf=graphical-session.target`
ties the daemon to a session that a gamescope boot may never start, and a mode
switch can stop it for the process lifetime. `After=pipewire.service` is the only
ordering the daemon needs, and both units resolve in user scope.

### Why print the drop-in instead of writing it?
The current code path uses `SetDiscoveryFilter` for scanning and
`LEAdvertisingManager1`, which is stable in BlueZ 5.48 and newer. The
experimental flag is therefore optional. Writing `/etc` from setup would demand
root for every install, and on SteamOS the file would disappear at the next OS
update unless it is allowlisted. Printing the content, the sudo command, and
the allowlist caveat keeps the default install unprivileged and keeps the
optional change explicit.

### Why Debian 11 and rustls?
A binary built on a newer distribution can require a newer glibc than SteamOS
provides, and the failure is a loader error at startup. Debian 11 defines the
oldest glibc the project supports (2.31), so an artifact built there loads on
SteamOS and on current desktop distributions. rustls avoids OpenSSL entirely,
which removes both the soname mismatch across distributions and the dependency
on a system OpenSSL version.

### Why the prebuilt path is primary on the Deck?
Building requires disabling the read-only root, installing a toolchain, and
rebuilding after every OS update. The prebuilt artifact avoids all three; the
source path stays available for regular desktops and packaging.

## Implementation
- `daemon/src/doctor.rs`: the check runner, probe set, and one-line output.
- `daemon/src/main.rs`: `seuil doctor` subcommand and non-fatal SDP startup.
- `daemon/src/setup.rs`: atomic config and unit writes, 0700 config directory,
  user-scope unit text, optional tool warnings, and the flag-gated drop-in.
- `install.sh`: `--from-release` with checksum verification and no toolchain,
  and optional-tool handling on the source path.
- `.github/workflows/release.yml`: Debian 11 build job with the `ldd` allowlist
  gate, stable asset name, and SHA-256 sidecar.
- `README.md`: Steam Deck section with Desktop Mode setup, the prebuilt path,
  and doctor verification.

## Verification
- `cargo check` and `cargo clippy --all-targets -- -D warnings` pass in
  `daemon/`.
- `bash -n install.sh` passes.
- The release workflow fails the portable job when `ldd` lists a library outside
  the glibc 2.31 allowlist or when the artifact does not run in the baseline
  container.
- Deck acceptance (Gaming Mode to Desktop Mode round trip, doctor exit
  contract) remains a live-device gate.

## Consequences
- A default setup writes nothing under `/etc` and needs no root after the
  binary is installed.
- The daemon survives session-mode switches and a Gaming Mode boot.
- A missing `sdptool` no longer stops startup, and the SDP check reports its own
  degradation.
- Release artifacts are larger than a native build because rustls is static, and
  the build job publishes one portable artifact instead of a per-distribution
  tarball.
- Users who want the experimental interfaces must run setup with the flag and
  add the allowlist fragment themselves.

## Alternatives considered

### System unit with a `/etc` install
Rejected: it needs root, writes outside `$HOME`, and every SteamOS update
removes it.

### Keep `PartOf=graphical-session.target`
Rejected: it stops the daemon on a session-mode switch and may never start it in
a pure gamescope session.

### Require the BlueZ experimental flag
Rejected: the current scan and advertise paths use stable interfaces, so the
flag adds a privileged system change for no functional gain.

### Build on Ubuntu 24.04
Rejected: the resulting glibc requirement is newer than SteamOS ships.

### OpenSSL instead of rustls
Rejected: it ties the artifact to a system OpenSSL soname and version, and
SteamOS updates can move it.

## References
- [`docs/requirements/FR-NFR-seuil-steamos-hardening.md`](../requirements/FR-NFR-seuil-steamos-hardening.md)
- [`specs/spec-steamos-deck-support.md`](../../specs/spec-steamos-deck-support.md)
- [`specs/spec-seuil-doctor.md`](../../specs/spec-seuil-doctor.md)

## Related Decisions
- Decision 001: Samsung Continuity implementation approach.
- Decision 002: Linux OAuth callback for Samsung sign-in.
