#!/bin/sh
# Re-record docs/assets/demo.gif. Needs Docker and a Linux tirnix binary
# for the container's architecture (VHS images exist for amd64 and arm64):
#   docs/demo/record.sh path/to/tirnix
set -eu
BIN="${1:?usage: record.sh path/to/linux/tirnix}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp "$BIN" "$WORK/tirnix"
cp "$HERE/setup.sh" "$HERE/demo.tape" "$WORK/"
docker run --rm --tmpfs /data:size=32m -v "$WORK":/vhs ghcr.io/charmbracelet/vhs demo.tape
cp "$WORK/demo.gif" "$HERE/../assets/demo.gif"
echo "Wrote $HERE/../assets/demo.gif"
