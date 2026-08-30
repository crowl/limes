#!/bin/zsh

set -euo pipefail

script_name="${0:t}"
label="com.crowl.limes"
repository="crowl/limes"

usage() {
  echo "Usage: ${script_name} <version>" >&2
}

die() {
  echo "${script_name}: $*" >&2
  exit 1
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

(( $# == 1 )) || { usage; exit 1; }
version="$1"
[[ "$version" =~ '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' ]] || die "version must be a stable release tag such as v0.3.0"
[[ "$(uname -s)" == "Darwin" ]] || die "macOS is required"
[[ -n "${HOME:-}" && -d "$HOME" ]] || die "HOME is not a usable directory"

for command in curl install launchctl plutil shasum tar; do
  command -v "$command" >/dev/null 2>&1 || die "$command is required"
done

case "$(uname -m)" in
  arm64) architecture="arm64" ;;
  x86_64) architecture="amd64" ;;
  *) die "unsupported macOS architecture: $(uname -m)" ;;
esac

script_directory="${0:A:h}"
source_launcher="${script_directory}/run.sh"
[[ -f "$source_launcher" && ! -L "$source_launcher" ]] || die "service launcher is missing: $source_launcher"

binary_directory="${HOME}/.local/bin"
libexec_directory="${HOME}/.local/libexec/limes"
launch_agent_directory="${HOME}/Library/LaunchAgents"
log_directory="${HOME}/Library/Logs/Limes"
configuration_directory="${XDG_CONFIG_HOME:-${HOME}/.config}/limes"
binary="${binary_directory}/limes"
launcher="${libexec_directory}/run"
plist="${launch_agent_directory}/${label}.plist"
configuration="${configuration_directory}/config.json"
environment="${configuration_directory}/environment"
domain="gui/$(id -u)"
service="${domain}/${label}"
asset="limes_${version}_darwin_${architecture}.tar.gz"
release_url="https://github.com/${repository}/releases/download/${version}"

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/limes-install.XXXXXX")" || die "cannot create a temporary directory"
cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM HUP
  rm -rf -- "$temporary_directory"
  exit "$exit_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

curl --proto '=https' --tlsv1.2 -fsSLo "${temporary_directory}/${asset}" "${release_url}/${asset}"
curl --proto '=https' --tlsv1.2 -fsSLo "${temporary_directory}/checksums.txt" "${release_url}/checksums.txt"

expected_checksum="$(awk -v asset="$asset" '$2 == asset || $2 == "*" asset { count++; checksum=$1 } END { if (count == 1) print checksum }' "${temporary_directory}/checksums.txt")"
[[ "$expected_checksum" =~ '^[0-9a-fA-F]{64}$' ]] || die "checksums.txt does not contain exactly one valid checksum for $asset"
actual_checksum="$(shasum -a 256 "${temporary_directory}/${asset}" | awk '{ print $1 }')"
[[ "$actual_checksum" == "$expected_checksum" ]] || die "checksum verification failed for $asset"

tar -xzf "${temporary_directory}/${asset}" -C "$temporary_directory" limes
[[ -f "${temporary_directory}/limes" && ! -L "${temporary_directory}/limes" ]] || die "release archive does not contain a regular limes binary"
release_version="$("${temporary_directory}/limes" -version)"
[[ "$release_version" == "limes ${version}"* ]] || die "downloaded binary reported unexpected version: $release_version"

install -d -m 0755 "$binary_directory" "$libexec_directory" "$launch_agent_directory" "$log_directory"
install -d -m 0700 "$configuration_directory"
install -m 0755 "${temporary_directory}/limes" "${binary}.new"
mv -f "${binary}.new" "$binary"
install -m 0755 "$source_launcher" "$launcher"

if [[ ! -e "$environment" ]]; then
  install -m 0600 /dev/null "$environment"
  echo "Created $environment; add the credentials referenced by $configuration before starting the service."
fi

[[ -f "$configuration" && ! -L "$configuration" ]] || die "configuration is required before installing the service: $configuration"
"$launcher" --check

plist_temporary="${temporary_directory}/${label}.plist"
plutil -create xml1 "$plist_temporary"
plutil -insert Label -string "$label" "$plist_temporary"
plutil -insert ProgramArguments -array "$plist_temporary"
plutil -insert ProgramArguments -string "$launcher" -append "$plist_temporary"
plutil -insert KeepAlive -bool true "$plist_temporary"
plutil -insert ThrottleInterval -integer 10 "$plist_temporary"
plutil -insert Umask -integer 63 "$plist_temporary"
plutil -insert EnvironmentVariables -dictionary "$plist_temporary"
plutil -insert EnvironmentVariables.HOME -string "$HOME" "$plist_temporary"
if [[ -n "${XDG_CONFIG_HOME:-}" ]]; then
  plutil -insert EnvironmentVariables.XDG_CONFIG_HOME -string "$XDG_CONFIG_HOME" "$plist_temporary"
fi
plutil -insert StandardOutPath -string "${log_directory}/stdout.log" "$plist_temporary"
plutil -insert StandardErrorPath -string "${log_directory}/stderr.log" "$plist_temporary"
plutil -lint "$plist_temporary" >/dev/null
install -m 0644 "$plist_temporary" "${plist}.new"
mv -f "${plist}.new" "$plist"

launchctl bootout "$service" >/dev/null 2>&1 || true
launchctl bootstrap "$domain" "$plist" || die "failed to bootstrap $label"
launchctl enable "$service"
launchctl kickstart -k "$service"

cat <<EOF
Installed Limes ${version}.
Binary:        ${binary}
Configuration: ${configuration}
Environment:   ${environment}
LaunchAgent:   ${plist}
Logs:          ${log_directory}
EOF
