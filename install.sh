#!/usr/bin/env bash
# Seuil installer: verify dependencies, build, install, and launch setup.
set -euo pipefail

NAME="seuil"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
BIN="${BIN_DIR}/${NAME}"

missing=()
check() {
    command -v "$1" >/dev/null 2>&1 || missing+=("$1")
}

echo "Checking build and runtime requirements"
check cargo
check bluetoothctl
check sdptool
check pw-dump
check playerctl
check systemctl
check pkg-config
if command -v pkg-config >/dev/null 2>&1; then
    pkg-config --exists dbus-1 || missing+=("dbus-1 development headers")
fi

if [[ ${#missing[@]} -ne 0 ]]; then
    echo
    echo "Missing requirements: ${missing[*]:-}"
    cat <<'HINTS'

Install them with:

  Arch:
    sudo pacman -S --needed base-devel pkg-config dbus bluez bluez-utils \
        bluez-deprecated-tools pipewire pipewire-pulse libpulse playerctl rust

  Debian / Ubuntu:
    sudo apt update && sudo apt install -y build-essential pkg-config \
        libdbus-1-dev libssl-dev bluez pipewire pipewire-bin \
        pipewire-pulse playerctl curl

  Fedora:
    sudo dnf install -y gcc pkg-config dbus-devel openssl-devel rust cargo \
        bluez bluez-deprecated pipewire pipewire-utils pipewire-pulseaudio playerctl

sdptool: Arch/CachyOS -> bluez-deprecated-tools, Debian/Ubuntu -> bluez,
Fedora -> bluez-deprecated.

Then re-run ./install.sh.
HINTS
    exit 1
fi

echo "Building ${NAME} (release)"
cargo build --release --locked --manifest-path "${ROOT}/daemon/Cargo.toml"

echo "Installing to ${BIN}"
install -Dm755 "${ROOT}/daemon/target/release/${NAME}" "${BIN}"

echo
echo "Launching ${NAME} setup"
exec "${BIN}" setup "$@"
