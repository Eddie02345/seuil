# Seuil

Pass Galaxy Buds audio between a Samsung phone and a Linux desktop without
touching either device. Seuil speaks Samsung's own Continuity protocol
(`com.samsung.android.mcfds`) over BLE and an L2CAP CoC, so the phone treats the
desktop as a real Continuity peer: the same handshake, the same Auto Switch
messages, the same silent handoff.

One name, one line: a *seuil* is the threshold of a doorway, the line a thing
crosses to change sides.

## How it works

```
        BLE 0x0075 advertisement                 L2CAP CoC (PSM from type-1 record)
phone <---------------------------> seuil <---------------------------------------> phone
        type 1 context + type 3 AD               AES-GCM handshake, then AES-CBC commands
```

1. **Advertisement.** Seuil broadcasts a Samsung manufacturer payload (company
   `0x0075`): header, rotating checksum, the account XOR seed, and an
   obfuscated LTV block. The type-1 record carries the LE CoC PSM. The type-3
   AD record carries the connected Buds' advertisement id and state flags, so
   the phone can map PSM owner to Buds and target a handoff.
2. **Channel.** The phone's `mcfds` app opens an LE Credit-Based CoC on that
   PSM. Seuil authenticates with the 3-message Samsung account handshake
   (AES-256-GCM AUTH_INITIATE / AUTH_INITIATE_REPLY / AUTH_REPLY, P-256 ECDH
   session key), then sends the Auto Switch ready event (`H=1, C=10, T=3`) and
   keeps the channel alive with a 15 s get-device-state query.
3. **Commands.** Auto Switch traffic uses handler 1: `BUDS_SWITCH` request
   (`C=1, T=1`) with the Buds address, advertisement id, and a reason byte
   (media or call); the phone answers `T=2` with a result. Seuil asks for the
   Buds when local playback starts, and releases them when the phone asks.
4. **Audio.** PipeWire stream state and MPRIS playback status drive the
   triggers. On a positive answer Seuil pulls the A2DP Sink profile through
   BlueZ; on a release it pauses MPRIS, drops A2DP/HFP, and answers the phone.

The wire format, message ids, and field layouts are documented in
[`docs/PROTOCOL_SPEC.md`](docs/PROTOCOL_SPEC.md).

## Supported hardware

- **Phone:** any Samsung device running One UI with the Continuity / Auto Switch
  service (`com.samsung.android.mcfds`), signed into a Samsung account.
- **Buds:** any Auto-Switch-capable Galaxy Buds: Buds+, Buds Live, Buds Pro,
  Buds2, Buds2 Pro, Buds FE, Buds Core (SM-R410), Buds3, Buds3 Pro.
- **Desktop:** Linux with BlueZ, PipeWire/PulseAudio, and a Bluetooth adapter
  that supports LE and A2DP.

## Requirements

| Distribution | Runtime packages | Build packages |
|---|---|---|
| Arch | `bluez bluez-utils dbus pipewire pipewire-pulse libpulse` | `base-devel rust` |
| Debian / Ubuntu | `bluez pipewire pipewire-bin pipewire-pulse playerctl libdbus-1-3` | `build-essential pkg-config libdbus-1-dev libssl-dev` |
| Fedora | `bluez bluez-deprecated pipewire pipewire-utils pipewire-pulseaudio playerctl dbus-libs` | `gcc pkg-config dbus-devel openssl-devel rust cargo` |

Runtime packages are enough for the prebuilt binaries. Source builds also need
the build packages; the per-distribution commands below include both.

`sdptool` is optional. It queries the phone's SDP records; without it, the
daemon skips that check and warns at startup. It ships in
`bluez-deprecated-tools` on Arch, `bluez` on Debian/Ubuntu, and
`bluez-deprecated` on Fedora. SteamOS bluez-utils ships no `sdptool`, and the
daemon runs without it. `pactl` and `parec` drive audio activity detection:
without them it degrades, and `seuil doctor` names the degraded source. They
ship together in `libpulse` on Arch and in `pulseaudio-utils` on Debian/Ubuntu
and Fedora. `playerctl` is optional for MPRIS control.

Seuil also needs the `bluer` crate's BlueZ backend, which is built from source
by Cargo.

## Installation

### Arch Linux

The Arch packaging lives in the AUR, community-maintained:
[seuil-git](https://aur.archlinux.org/packages/seuil-git) builds from this
repository's master branch.

```sh
paru -S seuil-git        # or: yay -S seuil-git
seuil setup
```

The portable prebuilt artifact also works on Arch without a package manager:
download the installer and run `bash install.sh --from-release`, which
installs into `~/.local/bin` (see the Steam Deck section for the full path).

### Debian / Ubuntu

Run these commands on recent Debian or Ubuntu (22.04+).

#### Prebuilt binary (no Rust toolchain)

```sh
sudo apt update && sudo apt install -y bluez pipewire pipewire-bin pipewire-pulse playerctl libdbus-1-3
mkdir -p ~/.local/bin
curl -fL https://github.com/Eddie02345/seuil/releases/latest/download/seuil-x86_64-unknown-linux-gnu.tar.gz | tar -xz -C ~/.local/bin
~/.local/bin/seuil setup
```

The same artifact is built on Debian 11 for glibc 2.31 and loads on current
distributions. `install.sh --from-release` automates the download, checksum
verification, and install; see the Steam Deck section for the full path.

#### Build from source via `./install.sh`

```sh
sudo apt update && sudo apt install -y build-essential pkg-config libdbus-1-dev libssl-dev bluez pipewire pipewire-bin pipewire-pulse playerctl curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
git clone https://github.com/Eddie02345/seuil.git
cd seuil
./install.sh
```

Installing Rust with `rustup` is recommended on Debian/Ubuntu: the distro
`cargo` package is often too old for current crates.

### Fedora

#### Prebuilt binary (no Rust toolchain)

```sh
sudo dnf install -y bluez bluez-deprecated pipewire pipewire-utils pipewire-pulseaudio playerctl dbus-libs
mkdir -p ~/.local/bin
curl -fL https://github.com/Eddie02345/seuil/releases/latest/download/seuil-x86_64-unknown-linux-gnu.tar.gz | tar -xz -C ~/.local/bin
~/.local/bin/seuil setup
```

#### Build from source via `./install.sh`

```sh
sudo dnf install -y gcc pkg-config dbus-devel openssl-devel rust cargo bluez bluez-deprecated pipewire pipewire-utils pipewire-pulseaudio playerctl
git clone https://github.com/Eddie02345/seuil.git
cd seuil
./install.sh
```

### First-run setup

The wizard (`seuil setup`, `seuil setup --reauth`):

1. enrolls the Samsung account (browser PKCE login and cloud certificate
   enrollment) when no credentials exist or `--reauth` is passed;
2. registers a temporary `ms-app://` handler, opens the sign-in page, and
   waits for the browser callback or a URL pasted into the terminal;
3. lists paired BlueZ devices with a likely role (phone or Buds) and asks for
   two list numbers. Press Enter to accept the default shown in brackets;
4. writes `~/.config/seuil/config.toml`, installs
   `~/.config/systemd/user/seuil.service`, reloads systemd, and enables and
   starts the service.

Setup accepts `--bt-address`, `--adapter`, and `--auth-server` before or after
the subcommand. `--debug` and `RUST_LOG` also apply to setup.

### Completing the Samsung Account sign-in on Linux

`seuil setup` registers Seuil as a temporary handler for Samsung's
`ms-app://` callback and opens the sign-in page in your default browser. After
you sign in:

- If the browser asks to open **Seuil Auth Callback**, choose **Open**. Seuil
  receives the callback over a local Unix socket and continues automatically.

If the browser stays on a loading spinner, or logs
`Prevented navigation to "ms-app://..." due to an unknown protocol`, it blocked
the redirect. The URL is still in the DevTools console:

1. Open the Console: `Ctrl + Shift + K` in Firefox or Zen,
   `Ctrl + Shift + J` in Chrome, Chromium, or Brave.
2. Find the `ms-app://s-1-15-2-...` entry. Copy the full URL or the whole
   console line.
3. Paste it into the terminal running `seuil setup` and press Enter.
   Surrounding quotes are fine. Do not paste it into the browser address bar.
4. If the code expired, restart `seuil setup --reauth` to generate a new one.

The temporary handler and socket are removed when sign-in finishes, fails, or
you press `Ctrl+C`. A browser that was already running can cache protocol
handlers, so the console paste path works even when the automatic handoff does
not.

If setup reports `could not read the address of hci0`, pass the adapter MAC
explicitly. The flag works before or after the subcommand:

```sh
seuil setup --bt-address XX:XX:XX:XX:XX:XX
```

Both devices must be paired in `bluetoothctl` first, and you need a Samsung
account.

## Steam Deck (SteamOS)

SteamOS keeps `/` read-only and replaces it on every OS update, so do not build
Seuil on the Deck. Install the prebuilt artifact into `$HOME`, run setup in
Desktop Mode, and verify with `seuil doctor`.

### Install the prebuilt binary

1. Switch to Desktop Mode: Steam button > Power > Switch to Desktop.
2. Download the installer and the current release artifact:

   ```sh
   curl -fLO https://raw.githubusercontent.com/Eddie02345/seuil/master/install.sh
   bash install.sh --from-release
   ```

   The script downloads `seuil-x86_64-unknown-linux-gnu.tar.gz`, verifies its
   published SHA-256 checksum, and installs it at `~/.local/bin/seuil`. It runs
   no compiler and no package manager. Pin a tag with
   `SEUIL_VERSION=v1.0.1 bash install.sh --from-release`.

   The artifact is built on Debian 11 (glibc 2.31) with rustls, so it links no
   OpenSSL and runs on SteamOS and current desktop distributions.

3. Add `~/.local/bin` to `PATH` if your shell does not already include it.

Nothing outside `$HOME` changes. `sdptool` is absent from SteamOS; the daemon
skips the phone SDP check with a warning and still runs. `pactl` and
`playerctl` may be absent too; audio detection degrades and doctor names the
source. Do not disable the read-only root to install them: updates wipe it.

### Run setup in Desktop Mode

```sh
~/.local/bin/seuil setup
```

Setup belongs in Desktop Mode because sign-in opens a browser and the daemon
needs your user session. It writes:

| Path | Contents |
|---|---|
| `~/.config/seuil/config.toml` | phone and Buds addresses |
| `~/.config/seuil/credentials.json`, `credentials.key` | encrypted Samsung account enrollment |
| `~/.config/systemd/user/seuil.service` | user unit, enabled and started |

The unit has no `graphical-session` dependency and orders only against user
targets, so it stays active when you switch between Gaming Mode and Desktop
Mode, and it starts on a pure Gaming Mode boot.

Setup prints an optional BlueZ experimental drop-in but writes nothing under
`/etc` unless you pass `--install-bluez-dropin`. The current code path does not
need it. If you install it, SteamOS 3.6 and newer keep `/etc` files only when
they are in its migration allowlist, so add an entry such as
`systemd/system/bluetooth.service.d/override.conf` to
`/etc/atomic-update.conf.d/` or the override is dropped on the next OS update.

### Verify with doctor

```sh
~/.local/bin/seuil doctor
```

One line per check. Exit 0 means every blocking check passed, 1 means a
blocking check failed (the line names the next action), and 2 means doctor
itself failed. Blocking checks are BlueZ reachability, adapter power, the
PipeWire socket, credentials, and an observed CoC PSM. The bluetoothd
experimental flag, the user unit state, and SteamOS detection are advisory and
never change the exit code.

## Usage

```
seuil                 # run the daemon (systemd does this at login)
seuil setup           # interactive setup
seuil setup --reauth  # re-enroll the Samsung account
seuil setup --bt-address XX:XX:XX:XX:XX:XX   # override adapter MAC detection
seuil setup --install-bluez-dropin   # also install the optional /etc drop-in
seuil doctor          # check dependencies and state; exit 0/1/2
seuil --phone AA:BB:CC:DD:EE:FF --buds 11:22:33:44:55:66   # flags override config
seuil --auth-login    # enroll or re-enroll the account
seuil --debug         # verbose logs
RUST_LOG=debug seuil  # verbose logs via the environment
```

`--debug` forces debug logging. `RUST_LOG` sets a custom filter when `--debug`
is not passed. Both apply to `seuil setup`.

Configuration lives in `~/.config/seuil/config.toml`:

```toml
phone_mac = "AA:BB:CC:DD:EE:FF"
buds_mac = "11:22:33:44:55:66"
# adapter = "hci0"
# device_name = "My PC"  # override the hostname shown on the phone
# discover = true   # fill missing MACs from the account device list / BlueZ
```

Credentials live beside it as `credentials.json` and `credentials.key` and are
AES-256-GCM encrypted with a local key.

## Troubleshooting

| Symptom | Check |
|---|---|
| Unsure why the service does not start | `seuil doctor`; blocking lines name the next action and the exit code is 1 |
| Service exits immediately | `journalctl --user -u seuil.service -n 50`; missing phone/Buds MACs point at `config.toml` |
| SDP warning at startup | `sdptool` is missing; optional, the daemon continues. Install `bluez-deprecated-tools` on Arch, `bluez` on Debian/Ubuntu, or `bluez-deprecated` on Fedora to restore the check |
| `could not read the address of hci0` | Pass the adapter MAC: `seuil setup --bt-address XX:XX:XX:XX:XX:XX` |
| `userKeyDecrypt fail` on the phone | Re-enroll: `seuil setup --reauth` (the account key no longer matches) |
| `Ctx={lost}` in phone logs | The advertisement type-1/type-3 records are malformed or the phone has not scanned yet; confirm the daemon advertised a 26-byte payload |
| `os error 107` / `104` on the CoC | The phone closed the app-side socket; check the phone's `mcfds` logcat, then the keepalive and reconnect ticks in the daemon log |
| `CONTINUITY_MSG_SPP NOT found on phone` | The phone is not exposing the Continuity SPP service yet; see the phone checklist below |
| Buds never move | BlueZ must see the Buds as paired; the phone must be unlocked once after boot for Auto Switch |
| No playback trigger | `playerctl -a status` should show `Playing`; browsers keep idle PipeWire nodes, so MPRIS is the reliable signal |

### Phone does not answer

If the log repeats `CONTINUITY_MSG_SPP NOT found on phone`, or the phone sends
nothing after the ready event, check these on the phone:

- Auto Switch / Continuity is enabled for the Buds.
- The phone and the Buds are signed into the same Samsung account.
- The Linux machine was enrolled with that same Samsung account.
- The phone has been unlocked at least once since boot.
- The Samsung Continuity service (`com.samsung.android.mcfds`) is running and
  allowed to run in the background.
- The Buds are connected to the phone before testing the handoff.

The first daemon start can take a few minutes to settle while the phone
discovers and authenticates the new Linux peer.

Logs: `journalctl --user -u seuil.service -f`.

## Development note

Parts of the protocol analysis, this documentation, and the Rust implementation
were built with an AI-assisted workflow using [OpenCode](https://opencode.ai).
Every packet structure, cryptographic operation, and audio handoff was reviewed
and verified live on Linux against physical Samsung hardware before release.

## Legal

Seuil is an independent, clean-room-style interoperable implementation. It
contains no Samsung application code, APKs, or decompiled binaries. Protocol
details were derived from observed traffic and the published behavior of the
Continuity service. Samsung, Galaxy, and Galaxy Buds are trademarks of Samsung
Electronics; this project is not affiliated with or endorsed by Samsung.

## License

GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
