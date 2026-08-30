#!/bin/sh

set -eu

fail() {
  echo "limes launcher: $*" >&2
  exit 1
}

home="${HOME:-}"
[ -n "$home" ] && [ -d "$home" ] || fail "HOME is not a usable directory"

configuration_directory="${XDG_CONFIG_HOME:-${home}/.config}/limes"
configuration="${configuration_directory}/config.json"
environment="${configuration_directory}/environment"
binary="${home}/.local/bin/limes"

validate_regular_file() {
  path="$1"
  description="$2"
  [ -f "$path" ] && [ ! -L "$path" ] || fail "$description must be a regular file and not a symbolic link: $path"
}

validate_regular_file "$binary" "binary"
validate_regular_file "$configuration" "configuration"
validate_regular_file "$environment" "environment file"

permissions="$(stat -f '%OLp' "$environment")" || fail "cannot inspect environment file permissions"
owner="$(stat -f '%u' "$environment")" || fail "cannot inspect environment file ownership"
[ "$owner" = "$(id -u)" ] || fail "environment file must be owned by the current user: $environment"
case "$permissions" in
  ???) ;;
  *) fail "cannot parse environment file permissions: $permissions" ;;
esac
case "$permissions" in
  ?00) ;;
  *) fail "environment file must not be accessible by group or others: $environment (mode $permissions)" ;;
esac

export_environment() {
  line="$1"
  case "$line" in
    ''|'#'*) return 0 ;;
  esac
  case "$line" in
    [A-Za-z_]*=*) ;;
    *) fail "invalid environment entry; expected NAME=VALUE" ;;
  esac
  name=${line%%=*}
  case "$name" in
    *[!A-Za-z0-9_]*|[0-9]*) fail "invalid environment variable name: $name" ;;
  esac
  value=${line#*=}
  export "$name=$value"
}

while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    *"$(printf '\r')") line=${line%"$(printf '\r')"} ;;
  esac
  export_environment "$line"
done < "$environment"

if [ "${1:-}" = "--check" ]; then
  [ "$#" -eq 1 ] || fail "--check does not accept arguments"
  exit 0
fi
[ "$#" -eq 0 ] || fail "unexpected argument: $1"

exec "$binary" --config-path "$configuration"
