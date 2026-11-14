# Contributing

Pull requests are welcome. Keep the protocol claims honest and the audio path
tested on real hardware.

## Before opening a pull request

- `cargo test` passes in `daemon/`.
- `cargo clippy --all-targets` reports no new warnings.
- The change keeps the evidence markers in `docs/PROTOCOL_SPEC.md` accurate:
  a claim that is not reproduced on hardware stays `[INFERRED]` or
  `[NEEDS VALIDATION]`.
- Commits are conventional (`fix:`, `feat:`, `docs:`, `refactor:`), and the
  pull request describes the user-visible effect, not just the diff.

## Changes to BLE, L2CAP CoC, crypto, or the PipeWire/MPRIS handoff

These areas fail silently, so a pull request that touches any of them must
include live verification evidence in the description:

- the `journalctl --user -u seuil.service` window showing the L2CAP CoC
  connect, the account handshake, and the `H=1, C=10, T=3` ready event;
- the matching `adb logcat` lines from the phone (`mcfds` / AutoSwitch
  handler) for the same window;
- the hardware used: phone model and One UI version, Buds model, distribution
  and kernel.

Changes without that evidence are reviewed as drafts and are not merged.

## AI-assisted work

AI assistance is allowed. The pull request must say that it was used and name
the human who reviewed the change and ran the hardware verification. That
person is accountable for the result. Do not submit generated protocol claims
that no one has checked against a device.

## License

By contributing you agree that your contribution is licensed under the GNU
General Public License v3.0 or later.
