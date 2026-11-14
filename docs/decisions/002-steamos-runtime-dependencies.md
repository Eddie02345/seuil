# Decision 002: SteamOS Runtime Dependencies

## Status

Accepted (2026-11-14), commit `5bf9321`.

## Context

SteamOS updates replace the read-only A/B system image. Packages installed
with `pacman` land in `/usr` and are removed by an image update. Files under
`/home`, `/opt`, and the bind-mounted Flatpak tree in `/var/lib/flatpak`
persist. A prebuilt Seuil install should therefore need no `pacman` packages
beyond what a stock Steam Deck already ships.

The previous requirement table listed `playerctl` for MPRIS playback status.
SteamOS does not ship it, so every Steam Deck user had to install it with
`pacman` and reinstall it after an OS update.

## Decision

Seuil depends only on runtime components present in the SteamOS image:

- BlueZ (`bluez`, `bluez-utils`, `bluez-deprecated-tools`)
- PipeWire and its PulseAudio compatibility layer (`pipewire`,
  `pipewire-pulse`, `libpulse`)
- D-Bus and systemd
- `xdg-utils` for the manual sign-in fallback

MPRIS playback status is read over the session D-Bus with the `mpris` crate
(`daemon/src/media/mod.rs`), not by running `playerctl`. `pactl` comes from
`libpulse`, which `pipewire-pulse` pulls in. `sdptool` remains optional and is
present in `bluez-deprecated-tools`; `daemon/src/sdp/mod.rs` falls back to
BlueZ's cached service UUIDs when it is absent.

The installer, package metadata, and documentation no longer mention
`playerctl` (`install.sh`, `packaging/aur/PKGBUILD`, `README.md`).

## Rationale

The SteamOS 3.7.20 package list contains `bluez`, `bluez-utils`,
`bluez-deprecated-tools`, `dbus`, `pipewire`, `pipewire-pulse`, `libpulse`,
`systemd`, `xdg-utils`, `curl`, and `tar`, but not `playerctl`
(<https://gist.github.com/hcartiaux/f5a901d048814dee7adec4830c9e8f5e>).
Using the already linked `mpris` crate removes the only missing runtime tool
without adding a package or a build dependency.

## Consequences

### Positive

- A prebuilt install needs no `pacman` command on SteamOS.
- MPRIS status uses the same D-Bus connection family as pause/resume, so there
  is one playback integration path instead of two.
- No post-update reinstall step for `playerctl`.

### Negative

- MPRIS enumeration now runs on a blocking task because the `mpris` crate is
  synchronous. The monitor polls every 750 ms, so the cost stays negligible.

### Neutral

- A source build still needs Rust and the D-Bus development headers. Those are
  build-time only and are not needed for the release tarball or the AUR binary.
- `bluetoothctl` remains an installer check because it confirms BlueZ tools are
  present and the setup instructions use it for pairing.

## References

- SteamOS 3.7.20 package list:
  <https://gist.github.com/hcartiaux/f5a901d048814dee7adec4830c9e8f5e>
- SteamOS partition and persistence notes:
  <https://github.com/randombk/steamos-teardown/blob/master/docs/partitions.md>
- Runtime check: `install.sh`
- MPRIS status: `daemon/src/media/mod.rs`
- Optional SDP fallback: `daemon/src/sdp/mod.rs`
