#!/usr/bin/env bash
# Seuil installer: build, install, and launch the interactive setup.
set -euo pipefail

NAME="seuil"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
BIN="${BIN_DIR}/${NAME}"

missing=0
check() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required tool: $1" >&2
        missing=1
    fi
}

echo "Checking runtime tools"
check cargo
check bluetoothctl
check pw-dump
check playerctl
check systemctl
if [[ $missing -ne 0 ]]; then
    echo
    echo "Install the missing tools and re-run ./install.sh."
    echo "  Arch:   sudo pacman -S bluez bluez-utils pipewire playerctl rust"
    echo "  Fedora: sudo dnf install bluez pipewire-utils playerctl cargo"
    echo "  Ubuntu: sudo apt install bluez pulseaudio-utils playerctl cargo"
    exit 1
fi

echo "Building ${NAME} (release)"
cargo build --release --manifest-path "${ROOT}/daemon/Cargo.toml"

echo "Installing to ${BIN}"
install -Dm755 "${ROOT}/daemon/target/release/${NAME}" "${BIN}"

echo
echo "Launching ${NAME} setup"
exec "${BIN}" setup "$@"
