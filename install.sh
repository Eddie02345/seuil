#!/usr/bin/env bash
# Seuil installer: install the prebuilt release or build from source (which then
# runs setup).
set -euo pipefail

NAME="seuil"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
BIN="${BIN_DIR}/${NAME}"
REPO="${SEUIL_REPO:-Eddie02345/seuil}"
ASSET="${NAME}-x86_64-unknown-linux-gnu.tar.gz"

FROM_RELEASE=0
setup_args=()
# Scratch paths live at script scope so the EXIT trap can remove them after
# install_from_release returns.
tmp=""
stage=""
for arg in "$@"; do
    case "$arg" in
        --from-release) FROM_RELEASE=1 ;;
        *) setup_args+=("$arg") ;;
    esac
done

# Installs the portable release artifact into ~/.local/bin. Uses no compiler,
# no package manager, and no Rust toolchain. [FR-002]
install_from_release() {
    local version="${SEUIL_VERSION:-latest}"
    local base
    if [[ "$version" == "latest" ]]; then
        base="https://github.com/${REPO}/releases/latest/download"
    else
        [[ "$version" == v* ]] || version="v${version}"
        base="https://github.com/${REPO}/releases/download/${version}"
    fi

    local url="${base}/${ASSET}"
    tmp="$(mktemp -d)"
    cleanup() {
        if [[ -n "$tmp" ]]; then
            rm -rf -- "$tmp"
        fi
        if [[ -n "$stage" ]]; then
            rm -rf -- "$stage"
        fi
        rm -f -- "${BIN}.new"
    }
    trap cleanup EXIT

    echo "Downloading ${url}"
    if ! curl -fL --proto '=https' --tlsv1.2 --retry 3 -o "${tmp}/${ASSET}" "$url"; then
        echo "error: could not download ${url}" >&2
        echo "Set SEUIL_VERSION to a published tag, for example SEUIL_VERSION=v1.0.1." >&2
        exit 1
    fi
    if ! curl -fsSL --proto '=https' --tlsv1.2 -o "${tmp}/${ASSET}.sha256" "${url}.sha256"; then
        echo "error: could not download the checksum ${url}.sha256" >&2
        echo "Nothing was installed." >&2
        exit 1
    fi

    if ! (cd "$tmp" && sha256sum -c "${ASSET}.sha256" >/dev/null); then
        echo "error: checksum verification failed for ${ASSET}" >&2
        echo "The download is incomplete or the release is corrupt; nothing was installed." >&2
        exit 1
    fi

    mkdir -p "$BIN_DIR"
    stage="$(mktemp -d "${BIN_DIR}/.seuil-install.XXXXXX")"
    if ! tar -xzf "${tmp}/${ASSET}" -C "$stage" "$NAME"; then
        echo "error: could not extract ${ASSET}" >&2
        exit 1
    fi
    if [[ ! -f "${stage}/${NAME}" ]]; then
        echo "error: ${ASSET} does not contain ${NAME}" >&2
        exit 1
    fi

    # Install through a sibling temporary name so a failed copy never leaves a
    # partial executable at ${BIN}.
    install -m755 "${stage}/${NAME}" "${BIN}.new"
    mv -f -- "${BIN}.new" "$BIN"

    echo "Installed ${BIN}"
    echo
    echo "Next steps, on a Steam Deck in Desktop Mode:"
    echo "  ${BIN} setup"
    echo "  ${BIN} doctor"
}

if [[ $FROM_RELEASE -eq 1 ]]; then
    missing_tools=()
    for tool in curl tar sha256sum install mktemp; do
        command -v "$tool" >/dev/null 2>&1 || missing_tools+=("$tool")
    done
    if [[ ${#missing_tools[@]} -ne 0 ]]; then
        echo "Missing tools for the prebuilt install: ${missing_tools[*]:-}" >&2
        echo "Install them with the system package manager; no Rust toolchain is needed." >&2
        exit 1
    fi
    install_from_release
    exit 0
fi

required=()
optional=()
check_required() {
    command -v "$1" >/dev/null 2>&1 || required+=("$1")
}
check_optional() {
    command -v "$1" >/dev/null 2>&1 || optional+=("$1")
}

echo "Checking build and runtime requirements"
check_required cargo
check_required bluetoothctl
check_required systemctl
check_required pkg-config
# Optional: absence degrades one feature and never stops the install. Doctor
# reports the same degradation after install.
check_optional sdptool
check_optional pactl
check_optional playerctl
if command -v pkg-config >/dev/null 2>&1; then
    pkg-config --exists dbus-1 || required+=("dbus-1 development headers")
fi

if [[ ${#required[@]} -ne 0 ]]; then
    echo
    echo "Missing requirements: ${required[*]:-}"
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

if [[ ${#optional[@]} -ne 0 ]]; then
    echo "Optional tools missing: ${optional[*]}"
    echo "The matching feature degrades; run \`seuil doctor\` after install for details."
fi

echo "Building ${NAME} (release)"
cargo build --release --locked --manifest-path "${ROOT}/daemon/Cargo.toml"

echo "Installing to ${BIN}"
install -Dm755 "${ROOT}/daemon/target/release/${NAME}" "${BIN}"

echo
echo "Launching ${NAME} setup"
exec "${BIN}" setup "${setup_args[@]}"
