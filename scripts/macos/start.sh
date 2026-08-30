#!/bin/zsh

set -euo pipefail

script_name="${0:t}"
label="com.crowl.limes"
domain="gui/$(id -u)"
service="${domain}/${label}"
plist="${HOME}/Library/LaunchAgents/${label}.plist"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  echo "Usage: ${script_name}"
  exit 0
fi
(( $# == 0 )) || { echo "Usage: ${script_name}" >&2; exit 1; }
[[ -f "$plist" ]] || { echo "${script_name}: Limes LaunchAgent is not installed: $plist" >&2; exit 1; }

if launchctl print "$service" >/dev/null 2>&1; then
  echo "$label is already running"
  exit 0
fi

launchctl bootstrap "$domain" "$plist"
launchctl enable "$service"
launchctl kickstart "$service"
echo "Started $label"
