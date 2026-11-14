# Seuil

Pass Galaxy Buds audio between a Samsung phone and a Linux desktop, including a
Steam Deck running SteamOS, without touching either device. Seuil speaks
Samsung's own Continuity protocol (`com.samsung.android.mcfds`) over BLE and an
L2CAP CoC, so the phone treats the desktop as a real Continuity peer: the same
handshake, the same Auto Switch messages, the same silent handoff.

One name, one line: a *seuil* is the threshold of a doorway, the line a thing
crosses to change sides.

## Highlights

- **SteamOS and Steam Deck:** a user-space install under `~/.local/bin` needs
  no `sudo steamos-readonly disable`, survives SteamOS A/B updates, and runs in
  both Gaming Mode and Desktop Mode through a systemd user service.
- **Multi-device:** use one Samsung Account with a Linux laptop, a Steam Deck,
  and the phone. Each machine gets its own persistent Continuity device id, so
  enrolling the Deck does not overwrite the laptop's registration.
- **No `sdptool` requirement:** service discovery reads BlueZ's cached SDP
  UUIDs natively, which matters on immutable SteamOS images.
- **Self-updating:** `seuil update` replaces a user-space binary from GitHub
  Releases, or use `./install.sh --from-source` to test a local checkout before
  the next release exists.

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
  Buds2, Buds2 Pro, Buds FE, Buds Core (SM-R410), Buds3, Buds3 Pro, Buds4,
  Buds4 Pro.
- **Desktop:** Linux with BlueZ, PipeWire/PulseAudio, and a Bluetooth adapter
  that supports LE and A2DP. This includes **SteamOS / Steam Deck** in both
  Desktop Mode and Gaming Mode.
- **Multiple Linux machines:** a laptop, desktop, and Steam Deck can share one
  Samsung Account. Each installation keeps a distinct device id.

## Requirements

| Distribution | Runtime packages | Build packages |
|---|---|---|
| SteamOS / Steam Deck | Preinstalled BlueZ, PipeWire, and libpulse; no extra runtime packages | Rust, `pkg-config`, and D-Bus headers only for source builds |
| Arch | `bluez bluez-utils dbus pipewire pipewire-pulse libpulse` | `base-devel rust` |
| Debian / Ubuntu | `bluez pipewire pipewire-bin pipewire-pulse libdbus-1-3` | `build-essential pkg-config libdbus-1-dev libssl-dev` |
| Fedora | `bluez pipewire pipewire-utils pipewire-pulseaudio dbus-libs` | `gcc pkg-config dbus-devel openssl-devel rust cargo` |

Runtime packages are enough for the prebuilt binaries. Source builds also need
the build packages; the per-distribution commands below include both. On
SteamOS, the prebuilt path writes only to `/home/deck`, so no read-only image
change is needed.

Seuil reads the phone's service UUIDs from BlueZ, so `sdptool` and
`bluez-deprecated-tools` are optional. Seuil also needs the `bluer` crate's
BlueZ backend, which is built from source by Cargo.

## Installation

### Steam Deck / SteamOS

Seuil installs entirely under `/home/deck`, so it survives SteamOS A/B updates
and never needs `sudo steamos-readonly disable` or a write to `/usr`.

1. Switch the Deck to **Desktop Mode**.
2. Open **System Settings → Bluetooth** and pair both the Samsung phone and the
   Galaxy Buds. Keep the phone unlocked while it confirms the pairing.
3. Install Seuil without a Rust toolchain:

   ```sh
   mkdir -p ~/.local/bin
   curl -L -o /tmp/seuil.tar.gz https://github.com/Eddie02345/seuil/releases/download/v1.0.1/seuil-v1.0.1-x86_64-unknown-linux-gnu.tar.gz
   tar -xzf /tmp/seuil.tar.gz -C ~/.local/bin
   chmod +x ~/.local/bin/seuil
   ~/.local/bin/seuil setup
   ```

   Or install from a cloned repository. This is the path to test unreleased
   changes before a new release tarball exists:

   ```sh
   git clone https://github.com/Eddie02345/seuil.git
   cd seuil
   ./install.sh --user --from-source
   ```

   `--from-source` runs `cargo build --release` and installs the checkout's
   `daemon/target/release/seuil`. The installer also switches to a source build
   automatically when `daemon/Cargo.toml` has a version newer than the latest
   GitHub release. Without either condition it downloads the published
   `x86_64` tarball. `install.sh` detects SteamOS automatically and uses
   user-space mode even without `--user`.

4. Double-click **Seuil Setup** on the Desktop to run the wizard again at any
   time. The executable shortcut runs
   `konsole --hold -e ~/.local/bin/seuil setup`, so no commands are needed on
   the on-screen keyboard and the terminal stays open if setup reports an error.
   The wizard writes `~/.config/seuil/config.toml`, installs
   `~/.config/systemd/user/seuil.service`, adds `~/.local/bin` to `PATH`, installs
   the Desktop shortcut, and enables and starts the user service.
5. Check the service in either Gaming Mode or Desktop Mode:

   ```sh
   systemctl --user status seuil.service
   journalctl --user -u seuil.service -f
   ```

The systemd user unit starts with the Steam session, so Auto Switch works in
both Gaming Mode and Desktop Mode. Everything lives in `/home/deck`:
`~/.local/bin/seuil`, `~/.config/seuil/`, and `~/.config/systemd/user/`. Update
the binary in place with `seuil update`.

### Arch Linux

The package is published with each GitHub release as a prebuilt
`.pkg.tar.zst`, so no AUR account is needed.

#### Prebuilt package

```sh
sudo pacman -U https://github.com/Eddie02345/seuil/releases/download/v1.0.1/seuil-1.0.1-1-x86_64.pkg.tar.zst
seuil setup
```

You can also download `seuil-<version>-1-x86_64.pkg.tar.zst` from the
[releases page](https://github.com/Eddie02345/seuil/releases) and install it
with `sudo pacman -U <file>`.

#### Build from source

```sh
sudo pacman -S --needed base-devel pkg-config dbus bluez bluez-utils \
    pipewire pipewire-pulse libpulse rust
git clone https://github.com/Eddie02345/seuil.git
cd seuil/packaging/aur
makepkg -si
seuil setup
```

AUR publishing (`paru -S seuil`, `yay -S seuil`) is queued until new AUR
account registration reopens. The package recipe in `packaging/aur` is already
ready and builds the same binary the release asset contains.

### Debian / Ubuntu

Run these commands on recent Debian or Ubuntu (22.04+).

#### Prebuilt binary (no Rust toolchain)

```sh
sudo apt update && sudo apt install -y bluez pipewire pipewire-bin pipewire-pulse libdbus-1-3
mkdir -p ~/.local/bin
curl -L -o /tmp/seuil.tar.gz https://github.com/Eddie02345/seuil/releases/download/v1.0.1/seuil-v1.0.1-x86_64-unknown-linux-gnu.tar.gz
tar -xzf /tmp/seuil.tar.gz -C ~/.local/bin
~/.local/bin/seuil setup
```

Substitute the latest tag from the
[releases page](https://github.com/Eddie02345/seuil/releases) if it is not
`v1.0.1`.

#### Build from source via `./install.sh`

```sh
sudo apt update && sudo apt install -y build-essential pkg-config libdbus-1-dev libssl-dev bluez pipewire pipewire-bin pipewire-pulse curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
git clone https://github.com/Eddie02345/seuil.git
cd seuil
./install.sh --from-source
```

Installing Rust with `rustup` is recommended on Debian/Ubuntu: the distro
`cargo` package is often too old for current crates.

### Fedora

#### Prebuilt binary (no Rust toolchain)

```sh
sudo dnf install -y bluez pipewire pipewire-utils pipewire-pulseaudio dbus-libs
mkdir -p ~/.local/bin
curl -L -o /tmp/seuil.tar.gz https://github.com/Eddie02345/seuil/releases/download/v1.0.1/seuil-v1.0.1-x86_64-unknown-linux-gnu.tar.gz
tar -xzf /tmp/seuil.tar.gz -C ~/.local/bin
~/.local/bin/seuil setup
```

#### Build from source via `./install.sh`

```sh
sudo dnf install -y gcc pkg-config dbus-devel openssl-devel rust cargo bluez pipewire pipewire-utils pipewire-pulseaudio
git clone https://github.com/Eddie02345/seuil.git
cd seuil
./install.sh --from-source
```

### First-run setup

The wizard (`seuil setup`, `seuil setup --reauth`):

1. enrolls the Samsung account (browser PKCE login and cloud certificate
   enrollment) when no credentials exist or `--reauth` is passed;
2. lists paired BlueZ devices with a likely role (phone or Buds) and asks for
   two numbers;
3. writes `~/.config/seuil/config.toml`, installs
   `~/.config/systemd/user/seuil.service`, reloads systemd, and enables and
   starts the service.

Both devices must be paired in `bluetoothctl` first, and you need a Samsung
account.

## Usage

```
seuil                 # run the daemon (systemd does this at login)
seuil setup           # interactive setup
seuil update          # replace ~/.local/bin/seuil with the latest release
seuil --phone AA:BB:CC:DD:EE:FF --buds 11:22:33:44:55:66   # flags override config
seuil --auth-login    # enroll or re-enroll the account
seuil --debug         # verbose logs
RUST_LOG=debug seuil  # choose a log filter with RUST_LOG
```

Configuration lives in `~/.config/seuil/config.toml`:

```toml
device_id = "0123456789abcdef0123456789abcdef"   # generated by setup; keep it stable per machine
phone_mac = "AA:BB:CC:DD:EE:FF"
buds_mac = "11:22:33:44:55:66"
# adapter = "hci0"
# discover = true   # fill missing MACs from the account device list / BlueZ
```

`device_id` distinguishes this machine from a laptop or Steam Deck enrolled under
the same Samsung Account. Setup derives it from `/etc/machine-id` and the
hostname on first install, then reuses the stored value on later runs and
upgrades, including ids carried over from older credentials files.

Credentials live beside it as `credentials.json` and `credentials.key` and are
AES-256-GCM encrypted with a local key.

## Troubleshooting

| Symptom | Check |
|---|---|
| Service exits immediately | `journalctl --user -u seuil.service -n 50`; missing phone/Buds MACs point at `config.toml` |
| `could not read the address of hci0` | Start `bluetoothd`, or pass `--bt-address AA:BB:CC:DD:EE:FF`; the address is read from sysfs, then BlueZ over D-Bus, then `hciconfig` |
| `sdptool: command not found` | Not required. Seuil reads service UUIDs from BlueZ; install `bluez-deprecated-tools` only as a fallback if your BlueZ build never caches them |
| Logs are too quiet | `RUST_LOG=debug` or `RUST_LOG=seuil=trace`; `--debug` sets the default filter to debug |
| `CONTINUITY_MSG_SPP NOT found on phone`, or no answer after `ready` | Enable Auto Switch on the phone, link the phone and the Galaxy Buds to the same Samsung Account, and unlock the phone during initial setup |
| `userKeyDecrypt fail` on the phone | Re-enroll: `seuil setup --reauth` (the account key no longer matches) |
| `Ctx={lost}` in phone logs | The advertisement type-1/type-3 records are malformed or the phone has not scanned yet; confirm the daemon advertised a 26-byte payload |
| `os error 107` / `104` on the CoC | The phone closed the app-side socket; check the phone's `mcfds` logcat, then the keepalive and reconnect ticks in the daemon log |
| Buds never move | BlueZ must see the Buds as paired; the phone must be unlocked once after boot for Auto Switch |
| No playback trigger | An MPRIS player must report `Playing`; browsers keep idle PipeWire nodes, so MPRIS is the reliable signal |

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
