#!/bin/zsh

set -euo pipefail

script_name="${0:t}"
label="com.crowl.limes"
service="gui/$(id -u)/${label}"
plist="${HOME}/Library/LaunchAgents/${label}.plist"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  echo "Usage: ${script_name}"
  exit 0
fi
(( $# == 0 )) || { echo "Usage: ${script_name}" >&2; exit 1; }

if launchctl print "$service" >/dev/null 2>&1; then
  launchctl print "$service"
  exit 0
fi

if [[ -f "$plist" ]]; then
  echo "$label is installed but not loaded"
  exit 1
fi

echo "$label is not installed"
exit 1
