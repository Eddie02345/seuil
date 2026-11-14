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

| Distribution | Packages |
|---|---|
| Arch | `bluez bluez-utils pipewire playerctl rust` |
| Fedora | `bluez pipewire-utils playerctl cargo` |
| Ubuntu | `bluez pulseaudio-utils playerctl cargo` |

Seuil also needs the `bluer` crate's BlueZ backend, which is built from source
by Cargo.

## Install

```sh
./install.sh
```

The script checks the runtime tools, builds the release binary, installs it to
`~/.local/bin/seuil`, and starts the interactive wizard. You need a Samsung
account and both devices paired in `bluetoothctl` first.

The wizard (`seuil setup`, `seuil setup --reauth`):

1. enrolls the Samsung account (browser PKCE login and cloud certificate
   enrollment) when no credentials exist or `--reauth` is passed;
2. lists paired BlueZ devices with a likely role (phone or Buds) and asks for
   two numbers;
3. writes `~/.config/seuil/config.toml`, installs
   `~/.config/systemd/user/seuil.service`, reloads systemd, and enables and
   starts the service.

## Usage

```
seuil                 # run the daemon (systemd does this at login)
seuil setup           # interactive setup
seuil --phone AA:BB:CC:DD:EE:FF --buds 11:22:33:44:55:66   # flags override config
seuil --auth-login    # enroll or re-enroll the account
seuil --debug         # verbose logs
```

Configuration lives in `~/.config/seuil/config.toml`:

```toml
phone_mac = "AA:BB:CC:DD:EE:FF"
buds_mac = "11:22:33:44:55:66"
# adapter = "hci0"
# discover = true   # fill missing MACs from the account device list / BlueZ
```

Credentials live beside it as `credentials.json` and `credentials.key` and are
AES-256-GCM encrypted with a local key.

## Troubleshooting

| Symptom | Check |
|---|---|
| Service exits immediately | `journalctl --user -u seuil.service -n 50`; missing phone/Buds MACs point at `config.toml` |
| `userKeyDecrypt fail` on the phone | Re-enroll: `seuil setup --reauth` (the account key no longer matches) |
| `Ctx={lost}` in phone logs | The advertisement type-1/type-3 records are malformed or the phone has not scanned yet; confirm the daemon advertised a 26-byte payload |
| `os error 107` / `104` on the CoC | The phone closed the app-side socket; check the phone's `mcfds` logcat, then the keepalive and reconnect ticks in the daemon log |
| Buds never move | BlueZ must see the Buds as paired; the phone must be unlocked once after boot for Auto Switch |
| No playback trigger | `playerctl -a status` should show `Playing`; browsers keep idle PipeWire nodes, so MPRIS is the reliable signal |

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
