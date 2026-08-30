#!/bin/zsh

set -euo pipefail

script_name="${0:t}"
label="com.crowl.limes"
service="gui/$(id -u)/${label}"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  echo "Usage: ${script_name}"
  exit 0
fi
(( $# == 0 )) || { echo "Usage: ${script_name}" >&2; exit 1; }

if ! launchctl print "$service" >/dev/null 2>&1; then
  echo "$label is not running"
  exit 0
fi

launchctl bootout "$service"
echo "Stopped $label"
