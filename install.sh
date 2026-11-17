#!/usr/bin/env bash
# Seuil installer: verify dependencies, build, install, and launch setup.
set -euo pipefail

if [ "${EUID}" = 0 ]; then
    echo "Please do not run this script as root"
    exit 1
fi

NAME="seuil"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${BIN_DIR:-${HOME}/.local/bin}"
BIN="${BIN_DIR}/${NAME}"
SERV_DIR="${SERV_DIR:-${HOME}/.config/systemd/user}"
SERVICE="${SERV_DIR}/${NAME}.service"

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

Then re-run ./install.sh.
HINTS
    exit 1
fi

echo "Building ${NAME} (release)"
cargo build --release --locked --manifest-path "${ROOT}/daemon/Cargo.toml"

echo "Installing to ${BIN}"
install -Dm755 "${ROOT}/daemon/target/release/${NAME}" "${BIN}"

echo "Creating ${SERVICE}"
mkdir -p ${SERV_DIR}
cat > ${SERVICE} << EOF
[Unit]
Description=Seuil Samsung Continuity daemon (Galaxy Buds Auto Switch)
After=pipewire.service bluetooth.target
Wants=pipewire.service
PartOf=graphical-session.target

[Service]
Type=simple
ExecStart=${BIN}
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info
ExecStartPre=-/usr/bin/bluetoothctl show

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload

echo
echo "Launching ${NAME} setup"
exec "${BIN}" setup "$@"
