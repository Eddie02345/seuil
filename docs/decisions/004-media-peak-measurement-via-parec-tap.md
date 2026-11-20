# Decision 004: Media peak measurement via a parec tap

## Status

Accepted (2026-11-20)

## Context

The active-audio rule (FR-016) counts a stream as active only when PipeWire
reports it RUNNING and its peak stays above the configured threshold (default
-60 dBFS) across the configured window (default 200 ms). Session gain (volume
and mute state) can only prefilter candidates: an unmuted, digitally-silent
stream must stay inactive, so the verdict needs the stream's actual sample
peak. Two mechanisms can read it: the `pipewire` crate as an in-process native
binding, or a subprocess tap through `parec --monitor-stream`.

## Decision

The daemon spawns `parec --monitor-stream=<index> --raw --format=s16le
--rate=48000 --channels=2` per RUNNING playback stream that passes the cheap
prefilter (uncorked, unmuted, media class), reads the raw samples from the
subprocess stdout, and computes each window's peak in the daemon as
`20*log10(max|sample|/32768)`. Taps are capped (four concurrent), reconciled
with the `pactl list sink-inputs` listing every poll, and killed on drop. The
`SEUIL_MEDIA_TAP` environment variable names a stub script for hermetic tests.

## Rationale

The native binding hard-links `libpipewire-0.3.so` into the portable release
artifact, which the Debian 11 build job's `ldd` linkage gate rejects (decision
003, FR-006), and it stops the daemon from loading at all on systems without
libpipewire. The subprocess tap adds no linkage, keeps the artifact portable,
and fits the existing probe pattern: `pactl` already requires the
pipewire-pulse server, the same server `parec` uses. A missing or failing
`parec` degrades with a held activity state and one persistent warning per
FR-018 rather than fabricating edges.

## Implementation

- `daemon/src/media/mod.rs`: `TapPool` (listing reconciliation, the cap),
  `StreamTap` (spawn, read, peak, kill on drop), `peak_dbfs`, `tap_command`,
  and the `SEUIL_MEDIA_TAP` stub hook.

## Verification

- `daemon/tests/media_test.rs` drives silent, loud, and mid-level (-26 dBFS)
  synthetic streams through the stub hook: the silent tab stays inactive,
  game audio produces exactly one start edge, and NFR-001's one-second
  settling holds.
- A dry run on live hardware starts the monitor at the configured
  -60 dBFS/200 ms window.

## Consequences

- A second optional runtime tool (`parec`, from pulseaudio-utils): absent
  tools degrade to a held state with a warning; the doctor and installer do
  not yet name it.
- Playback streams beyond the tap cap are not measured; the cap logs once.
- A digitally-silent stream at unity gain stays inactive, closing FR-016's
  silent-tab case.

## Alternatives considered

### The `pipewire` crate

Rejected: it hard-links `libpipewire-0.3.so` into the portable artifact,
fails the Debian 11 `ldd` linkage gate, and prevents the binary from loading
on systems without the library.

### Session gain as a dBFS ceiling

Rejected: an unmuted, digitally-silent stream at normal volume still reads
active, which is exactly the false positive FR-016 exists to eliminate.

### Parsing `pw-top` output

Rejected: fragile TUI scraping for the same data the tap reads as raw bytes.
