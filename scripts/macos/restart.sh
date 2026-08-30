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
[[ -f "$plist" ]] || { echo "${script_name}: Limes LaunchAgent is not installed: $plist" >&2; exit 1; }

launchctl kickstart -k "$service"
echo "Restarted $label"
