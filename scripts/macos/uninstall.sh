#!/bin/zsh

set -euo pipefail

script_name="${0:t}"
label="com.crowl.limes"
service="gui/$(id -u)/${label}"
plist="${HOME}/Library/LaunchAgents/${label}.plist"
launcher_directory="${HOME}/.local/libexec/limes"

usage() {
  echo "Usage: ${script_name} [--purge]"
}

purge=false
case "${1:-}" in
  '') ;;
  --purge) purge=true ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 1 ;;
esac
(( $# <= 1 )) || { usage >&2; exit 1; }

launchctl bootout "$service" >/dev/null 2>&1 || true
rm -f -- "$plist"
rm -rf -- "$launcher_directory"

if $purge; then
  rm -f -- "${HOME}/.local/bin/limes"
  echo "Removed the LaunchAgent, launcher, and installed Limes binary."
else
  echo "Removed the LaunchAgent and launcher. The binary and configuration were preserved."
fi
