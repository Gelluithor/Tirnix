#!/bin/sh
# Tirnix uninstaller (for installs made with install.sh).
#
#   sh uninstall.sh [--dir DIR] [--system] [--purge] [--yes]
#
# By default this stops the logger (if one is running for the current user)
# and removes the `tirnix` binary. Configuration and stored history are kept
# unless --purge is given. Packages (.deb/.rpm) must be removed with apt/dnf.
set -eu

DIR=""
PURGE=0
YES=0

say() { printf '%s\n' "$*"; }
die() { printf 'uninstall.sh: error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --dir) [ $# -ge 2 ] || die "--dir needs a value"; DIR="$2"; shift 2 ;;
        --dir=*) DIR="${1#--dir=}"; shift ;;
        --system) DIR="/usr/local/bin"; shift ;;
        --purge) PURGE=1; shift ;;
        -y|--yes) YES=1; shift ;;
        -h|--help)
            say "Usage: uninstall.sh [--dir DIR] [--system] [--purge] [--yes]"
            say "  --dir DIR  directory the binary was installed to (default: \$HOME/.local/bin)"
            say "  --system   the binary is in /usr/local/bin"
            say "  --purge    also delete config (~/.config/tirnix) and data (~/.local/state/tirnix)"
            say "  --yes      do not ask for confirmation"
            exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

[ -n "$DIR" ] || DIR="${HOME:?HOME is not set}/.local/bin"
BIN="$DIR/tirnix"

CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/tirnix"
DATA_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/tirnix"

if [ -x "$BIN" ]; then
    # Stop (and disable) background logging of this user, if any.
    "$BIN" logger stop >/dev/null 2>&1 || true
    rm -f "$BIN"
    say "Removed $BIN"
else
    say "No tirnix binary at $BIN (nothing to remove there)."
fi

if command -v systemctl >/dev/null 2>&1 &&
    systemctl --user is-enabled tirnix-logger.service >/dev/null 2>&1; then
    say "Note: the user service tirnix-logger.service is still enabled."
    say "      Disable it with: systemctl --user disable --now tirnix-logger.service"
fi

if [ "$PURGE" -eq 1 ]; then
    if [ "$YES" -ne 1 ]; then
        printf 'Delete %s and %s (configuration and all stored history)? [y/N] ' "$CONFIG_DIR" "$DATA_DIR"
        read -r answer </dev/tty || answer=""
        case "$answer" in
            y|Y|yes|YES) ;;
            *) say "Kept configuration and data."; exit 0 ;;
        esac
    fi
    rm -rf "$CONFIG_DIR" "$DATA_DIR"
    say "Removed $CONFIG_DIR and $DATA_DIR"
else
    [ -d "$CONFIG_DIR" ] && say "Kept configuration: $CONFIG_DIR"
    [ -d "$DATA_DIR" ] && say "Kept stored history: $DATA_DIR"
    say "Run with --purge to delete them as well."
fi
