#!/usr/bin/env bash
# Seuil installer: verify dependencies, install a release or local build, and
# launch setup.
#
# User-space mode is the default for normal users and is forced on SteamOS.
# Pass --user, --system, or --from-source to choose explicitly.
set -euo pipefail

NAME="seuil"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_SLUG="Eddie02345/seuil"
ASSET_SUFFIX="x86_64-unknown-linux-gnu.tar.gz"
USER_MODE=false
SYSTEM_MODE=false
FROM_SOURCE=false
SETUP_ARGS=()

for arg in "$@"; do
    case "${arg}" in
        --user) USER_MODE=true ;;
        --system) SYSTEM_MODE=true ;;
        --from-source) FROM_SOURCE=true ;;
        *) SETUP_ARGS+=("${arg}") ;;
    esac
done

is_steamos() {
    [[ -r /etc/os-release ]] && grep -qE '^ID="?steamos"?$' /etc/os-release
}

if [[ "${USER_MODE}" == false && "${SYSTEM_MODE}" == false ]]; then
    if is_steamos; then
        USER_MODE=true
    elif [[ "${EUID}" -ne 0 ]]; then
        USER_MODE=true
    fi
fi

if [[ "${USER_MODE}" == true && "${SYSTEM_MODE}" == true ]]; then
    echo "Choose either --user or --system, not both." >&2
    exit 2
fi

if [[ "${USER_MODE}" == true ]]; then
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        TARGET_HOME="$(getent passwd "${SUDO_USER}" 2>/dev/null | cut -d: -f6)"
        [[ -n "${TARGET_HOME}" ]] || TARGET_HOME="${HOME}"
    else
        TARGET_HOME="${HOME}"
    fi
    export HOME="${TARGET_HOME}"
    BIN_DIR="${TARGET_HOME}/.local/bin"
    echo "User-space install for ${TARGET_HOME}"
else
    if [[ "${EUID}" -ne 0 ]]; then
        echo "A system install writes to /usr/local/bin; re-run with sudo or use --user." >&2
        exit 2
    fi
    TARGET_HOME="${HOME}"
    BIN_DIR="/usr/local/bin"
fi
BIN="${BIN_DIR}/${NAME}"

LOCAL_CARGO="${ROOT}/daemon/Cargo.toml"
LOCAL_VERSION=""
if [[ -f "${LOCAL_CARGO}" ]]; then
    LOCAL_VERSION="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${LOCAL_CARGO}" | head -n1)"
fi

latest_release_tag() {
    command -v curl >/dev/null 2>&1 || return 1
    curl -fsSL --connect-timeout 10 --max-time 30 \
        -H 'Accept: application/vnd.github+json' \
        "https://api.github.com/repos/${REPO_SLUG}/releases/latest" \
        | sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n1
}

version_gt() {
    local left right
    left="$(printf '%s' "${1#v}" | sed -E 's/[^0-9.].*$//')"
    right="$(printf '%s' "${2#v}" | sed -E 's/[^0-9.].*$//')"
    [[ -n "${left}" && -n "${right}" && "${left}" != "${right}" ]] || return 1
    [[ "$(printf '%s\n%s\n' "${left}" "${right}" | sort -V | tail -n1)" == "${left}" ]]
}

INSTALL_METHOD="release"
RELEASE_TAG=""
if [[ "${FROM_SOURCE}" == true ]]; then
    if [[ -z "${LOCAL_VERSION}" ]]; then
        echo "--from-source needs a cloned repository with daemon/Cargo.toml." >&2
        exit 2
    fi
    INSTALL_METHOD="source"
else
    RELEASE_TAG="$(latest_release_tag || true)"
    if [[ -n "${LOCAL_VERSION}" ]]; then
        if [[ -z "${RELEASE_TAG}" ]]; then
            echo "Could not read the latest release; building the local source"
            INSTALL_METHOD="source"
        elif version_gt "${LOCAL_VERSION}" "${RELEASE_TAG}"; then
            echo "Local version ${LOCAL_VERSION} is newer than release ${RELEASE_TAG}; building the local source"
            INSTALL_METHOD="source"
        fi
    elif [[ -z "${RELEASE_TAG}" ]]; then
        echo "No local source tree and no GitHub release available to install." >&2
        exit 1
    fi
fi

missing=()
check() {
    command -v "$1" >/dev/null 2>&1 || missing+=("$1")
}

echo "Checking build and runtime requirements"
check bluetoothctl
check systemctl
if [[ "${INSTALL_METHOD}" == "source" ]]; then
    check cargo
    check pkg-config
    if command -v pkg-config >/dev/null 2>&1; then
        pkg-config --exists dbus-1 || missing+=("dbus-1 development headers")
    fi
else
    check curl
    check tar
fi

if [[ ${#missing[@]} -ne 0 ]]; then
    echo
    echo "Missing requirements: ${missing[*]:-}"
    cat <<'HINTS'

Install the runtime packages with:

  Arch:
    sudo pacman -S --needed bluez bluez-utils dbus pipewire pipewire-pulse \
        libpulse curl

  Debian / Ubuntu:
    sudo apt update && sudo apt install -y bluez pipewire pipewire-bin \
        pipewire-pulse curl

  Fedora:
    sudo dnf install -y bluez pipewire pipewire-utils pipewire-pulseaudio \
        curl

For a source build also install:

  Arch:            sudo pacman -S --needed base-devel rust
  Debian / Ubuntu: sudo apt install -y build-essential pkg-config libdbus-1-dev libssl-dev
  Fedora:          sudo dnf install -y gcc pkg-config dbus-devel openssl-devel rust cargo

sdptool is no longer required: Seuil reads service UUIDs from BlueZ natively.

On SteamOS, the prebuilt release path needs no Rust toolchain or
steamos-readonly changes. See the Steam Deck / SteamOS section in README.md.

Then re-run ./install.sh.
HINTS
    exit 1
fi

install_from_release() {
    local tag="$1"
    local url="https://github.com/${REPO_SLUG}/releases/download/${tag}/${NAME}-${tag}-${ASSET_SUFFIX}"
    local tmp
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/seuil-install.XXXXXX")"

    echo "Downloading ${NAME} ${tag}"
    if ! curl -fL --retry 3 --connect-timeout 15 -o "${tmp}/seuil.tar.gz" "${url}"; then
        rm -rf "${tmp}"
        return 1
    fi
    if ! tar -xzf "${tmp}/seuil.tar.gz" -C "${tmp}" || [[ ! -f "${tmp}/${NAME}" ]]; then
        rm -rf "${tmp}"
        return 1
    fi
    if ! install -Dm755 "${tmp}/${NAME}" "${BIN}"; then
        rm -rf "${tmp}"
        return 1
    fi
    rm -rf "${tmp}"
}

install_from_source() {
    echo "Building ${NAME} ${LOCAL_VERSION} (release)"
    cargo build --release --locked --manifest-path "${LOCAL_CARGO}"
    install -Dm755 "${ROOT}/daemon/target/release/${NAME}" "${BIN}"
}

if [[ "${INSTALL_METHOD}" == "release" ]]; then
    echo "Installing to ${BIN}"
    if ! install_from_release "${RELEASE_TAG}"; then
        if [[ -n "${LOCAL_VERSION}" ]] \
            && command -v cargo >/dev/null 2>&1 \
            && command -v pkg-config >/dev/null 2>&1 \
            && pkg-config --exists dbus-1; then
            echo "warning: release download failed; building the local source instead"
            INSTALL_METHOD="source"
        else
            echo "Could not download ${NAME} ${RELEASE_TAG}." >&2
            echo "Re-run with --from-source after installing the source build requirements." >&2
            exit 1
        fi
    fi
fi

if [[ "${INSTALL_METHOD}" == "source" ]]; then
    echo "Installing to ${BIN}"
    install_from_source
fi

export PATH="${BIN_DIR}:${PATH}"

if [[ "${USER_MODE}" == true ]]; then
    BASHRC="${TARGET_HOME}/.bashrc"
    if ! grep -qF '$HOME/.local/bin' "${BASHRC}" 2>/dev/null \
        && ! grep -qF '${HOME}/.local/bin' "${BASHRC}" 2>/dev/null; then
        printf '\n# Added by Seuil\nif [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then\n    export PATH="$HOME/.local/bin:$PATH"\nfi\n' \
            >>"${BASHRC}"
        echo "Added ~/.local/bin to PATH in ${BASHRC}"
    fi

    UNIT_DIR="${TARGET_HOME}/.config/systemd/user"
    mkdir -p "${UNIT_DIR}"
    cat >"${UNIT_DIR}/seuil.service" <<EOF
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
    systemctl --user daemon-reload || echo "warning: could not reload the user systemd manager"
    systemctl --user enable seuil.service || echo "warning: could not enable seuil.service"

    DESKTOP_DIR="${TARGET_HOME}/Desktop"
    mkdir -p "${DESKTOP_DIR}"
    cat >"${DESKTOP_DIR}/Seuil Setup.desktop" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=Seuil Setup
Comment=Pair the Samsung phone and Galaxy Buds with Seuil
Exec=konsole --hold -e ${BIN} setup
Terminal=false
Icon=preferences-system-bluetooth
Categories=Utility;
EOF
    chmod 755 "${DESKTOP_DIR}/Seuil Setup.desktop"
    echo "Installed the setup shortcut at ${DESKTOP_DIR}/Seuil Setup.desktop"
fi

echo
echo "Launching ${NAME} setup"
"${BIN}" setup "${SETUP_ARGS[@]}"

if systemctl --user enable --now seuil.service; then
    echo "Enabled and started seuil.service"
else
    echo "warning: could not start seuil.service; check systemctl --user status seuil.service"
fi
