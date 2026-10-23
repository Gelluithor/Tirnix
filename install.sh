#!/bin/sh
# Tirnix installer.
#
#   curl -fsSL https://raw.githubusercontent.com/Gelluithor/Tirnix/main/install.sh | sh
#   sh install.sh [--version X.Y.Z] [--dir DIR] [--system]
#
# * Downloads a prebuilt static Linux binary from GitHub Releases.
# * Verifies it against the release's SHA256SUMS before installing.
# * Installs only the `tirnix` binary. Nothing else is changed: no config,
#   no data directory, no systemd service, no background process.
# * Default target: ~/.local/bin (no root needed). Use --system for
#   /usr/local/bin (needs root).
set -eu

REPO="${TIRNIX_REPO:-Gelluithor/Tirnix}"
VERSION=""
DIR=""

say() { printf '%s\n' "$*"; }
die() { printf 'install.sh: error: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: install.sh [--version X.Y.Z] [--dir DIR] [--system]

  --version X.Y.Z   Install this release (default: latest)
  --dir DIR         Install into DIR (default: \$HOME/.local/bin)
  --system          Install into /usr/local/bin (requires root)
  -h, --help        Show this help

Environment:
  TIRNIX_REPO=owner/name     install from a fork
  TIRNIX_BASE_URL=URL        download assets from a mirror instead of GitHub
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION="${2#v}"; shift 2 ;;
        --version=*) VERSION="${1#--version=}"; VERSION="${VERSION#v}"; shift ;;
        --dir) [ $# -ge 2 ] || die "--dir needs a value"; DIR="$2"; shift 2 ;;
        --dir=*) DIR="${1#--dir=}"; shift ;;
        --system) DIR="/usr/local/bin"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
done

[ "$(uname -s)" = "Linux" ] || die "Tirnix supports Linux only (detected $(uname -s))."

case "$(uname -m)" in
    x86_64|amd64) TARGET="x86_64-unknown-linux-musl" ;;
    aarch64|arm64) TARGET="aarch64-unknown-linux-musl" ;;
    *) die "no prebuilt binary for architecture $(uname -m); build from source with: cargo install --git https://github.com/$REPO" ;;
esac

if [ -z "$DIR" ]; then
    [ -n "${HOME:-}" ] || die "HOME is not set; use --dir"
    DIR="$HOME/.local/bin"
fi

# HTTPS only, unless TIRNIX_BASE_URL explicitly points elsewhere.
PROTO="=https"
case "${TIRNIX_BASE_URL:-}" in "" | https://*) ;; *) PROTO="=https,http,file" ;; esac
if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL --proto "$PROTO" --tlsv1.2 --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
    if [ "$PROTO" = "=https" ]; then
        fetch() { wget -q --https-only -O "$2" "$1"; }
    else
        fetch() { wget -q -O "$2" "$1"; }
    fi
else
    die "curl or wget is required"
fi

if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
    die "sha256sum or shasum is required to verify the download"
fi

if [ -n "${TIRNIX_BASE_URL:-}" ]; then
    # Mirror of the release assets (an explicit choice of the user).
    BASE="${TIRNIX_BASE_URL%/}"
elif [ -n "$VERSION" ]; then
    BASE="https://github.com/$REPO/releases/download/v$VERSION"
else
    BASE="https://github.com/$REPO/releases/latest/download"
fi
ASSET="tirnix-$TARGET.tar.gz"

TMP="$(mktemp -d 2>/dev/null || mktemp -d -t tirnix)"
trap 'rm -rf "$TMP"' EXIT INT TERM

say "Downloading $ASSET from $BASE ..."
fetch "$BASE/$ASSET" "$TMP/$ASSET" || die "download failed: $BASE/$ASSET"
fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" || die "download failed: $BASE/SHA256SUMS"

EXPECTED="$(awk -v f="$ASSET" '$2 == f || $2 == "*"f { print $1 }' "$TMP/SHA256SUMS")"
[ -n "$EXPECTED" ] || die "$ASSET is not listed in SHA256SUMS"
ACTUAL="$(sha256 "$TMP/$ASSET")"
[ "$EXPECTED" = "$ACTUAL" ] || die "checksum mismatch for $ASSET (expected $EXPECTED, got $ACTUAL)"
say "Checksum OK ($ACTUAL)."

mkdir -p "$TMP/x"
tar -xzf "$TMP/$ASSET" -C "$TMP/x"
BIN="$(find "$TMP/x" -type f -name tirnix | head -n 1)"
[ -n "$BIN" ] || die "archive does not contain a tirnix binary"
NEW_VERSION="$("$BIN" --version 2>/dev/null || true)"
[ -n "$NEW_VERSION" ] || die "downloaded binary does not run on this system"

if [ ! -d "$DIR" ]; then
    mkdir -p "$DIR" || die "cannot create $DIR (try --dir or run as root for --system)"
fi
[ -w "$DIR" ] || die "$DIR is not writable (use --dir, or run as root for --system)"

DEST="$DIR/tirnix"
if [ -x "$DEST" ]; then
    say "Replacing $("$DEST" --version 2>/dev/null || echo 'existing tirnix') in $DIR"
fi
# Copy next to the destination, then rename: the switch is atomic and a
# running tirnix (e.g. the logger) keeps its old binary until restarted.
cp "$BIN" "$DEST.new.$$"
chmod 755 "$DEST.new.$$"
mv -f "$DEST.new.$$" "$DEST"

say "Installed $NEW_VERSION to $DEST"
case ":${PATH:-}:" in
    *":$DIR:"*) ;;
    *) say "Note: $DIR is not on your PATH. Add it, e.g.: export PATH=\"$DIR:\$PATH\"" ;;
esac
say "Run 'tirnix' to start. Long-term logging is off until you enable it in Settings."
if "$DEST" logger status 2>/dev/null | grep -q 'running (pid'; then
    say "A Tirnix logger is running; restart it to use the new version: tirnix logger stop && tirnix logger start"
fi
