# Limes

<p align="center">
  <img src="docs/limes.jpg" alt="Limes" width="600">
</p>

Limes is a local credential boundary for HTTP clients. A client sends a request
with a placeholder credential; Limes validates the destination and route,
removes caller-provided credentials, injects a credential held by the host, and
forwards the request to the configured upstream.

This keeps API keys, access tokens, and subscription credentials out of clients
that need to exercise their authority without possessing the underlying secret.
Useful clients include sandboxed processes, containers, development tools,
automation, and local applications.

Requests and responses are streamed without automatic retries.

## Security model

Limes protects credential material, not the authority granted by that credential.
A client can perform every operation permitted by the configured routes and the
upstream credential while it can reach Limes. Use narrowly scoped credentials
and narrowly defined routes.

Limes does not authenticate incoming clients. Bind listeners to loopback unless
they must be reached from a local VM or container, and do not expose them to
untrusted networks. When a non-loopback listener is required, rely on host
firewall and virtualization boundaries to restrict access.

The generic backends accept only configured routes and upstreams. Caller-provided
credential headers are always replaced. Limes does not retry requests, so it
does not duplicate non-idempotent operations.

## Installation

Limes requires Go 1.27.0 when building from source:

```sh
go build -o limes .
./limes -version
mkdir -p ~/.config/limes
cp config.example.json ~/.config/limes/config.json
./limes
```

Set the environment variables referenced by the configuration before starting
Limes.

To use another configuration file:

```sh
./limes --config-path ./config.json
```

Without `--config-path`, Limes looks in:

1. `$XDG_CONFIG_HOME/limes/config.json`
2. `$HOME/.config/limes/config.json`

See [Running as a macOS service](#running-as-a-macos-service) for installation
from a release and automatic startup at login.

## Configuration

A configuration may enable the self-contained admin panel on a loopback address:

```json
{
  "admin": {
    "address": "127.0.0.1:8799"
  },
  "listeners": [
    "..."
  ]
}
```

Open `http://127.0.0.1:8799/` to inspect listeners and switch between their
available backends without restarting Limes. Switching affects new requests;
in-flight requests finish on the backend that accepted them. The selection is
held only in memory, so restarting Limes restores the first available backend in
configuration order.

The admin panel is disabled when `admin` is omitted. Its address must use
`localhost` or a loopback IP and cannot match a proxy listener address. It shows
sanitized availability information and never displays credentials. Backend
availability is evaluated during startup; restart Limes after adding or fixing a
credential.

If a listener has no available backend, it is not bound but remains visible in
the admin panel. Limes can run with only the admin panel when every backend is
unavailable. Without an enabled admin panel, Limes exits when no backend is
available.

A configuration defines one or more listeners and an ordered list of backend
candidates for each listener. The first available candidate is active at startup:

```json
{
  "listeners": [
    {
      "name": "example",
      "address": "127.0.0.1:8787",
      "backends": [
        {
          "type": "http",
          "upstream": "https://api.example.com",
          "routes": [
            { "method": "POST", "path": "/v1/messages" }
          ],
          "remove_headers": ["Authorization"],
          "credential": {
            "environment": "EXAMPLE_API_KEY",
            "header": "Authorization",
            "prefix": "Bearer "
          }
        }
      ]
    }
  ]
}
```

### HTTP backend

The generic `http` backend:

- Forwards only configured method and path combinations
- Removes configured headers and query parameters
- Replaces the configured credential header
- Reads the credential from a host environment variable
- Supports upstream path prefixes
- Streams upstream responses

Configure a client with the listener URL and any nonempty placeholder credential
it requires. The real credential remains in the Limes process environment.

### HTTPS backend

The generic `https` backend is an explicit HTTPS proxy. It accepts `CONNECT`
requests only for configured upstream origins, terminates client TLS with the
Limes CA, applies the same route and credential rules as `http`, and opens a
separately verified TLS connection to the selected upstream.

Initialize the persistent CA before enabling an `https` backend:

```sh
limes ca init
limes ca status
limes ca certificate > limes-ca.pem
```

The CA private key remains in the Limes configuration directory. Install or mount
only the public certificate in clients that use an `https` backend. The CA can
issue a certificate for each configured upstream, so clients should trust it only
where interception by Limes is intended.

Rotate the CA explicitly when needed:

```sh
limes ca rotate --force
```

Clients trusting the previous CA must be updated after rotation.

An `https` backend uses `upstreams` because the `CONNECT` authority selects among
fixed origins:

```json
{
  "type": "https",
  "upstreams": [
    "https://github.com",
    "https://api.github.com"
  ],
  "routes": [
    { "method": "GET", "path": "/{path...}" },
    { "method": "HEAD", "path": "/{path...}" },
    { "method": "POST", "path": "/{path...}" }
  ],
  "remove_headers": ["Authorization"],
  "credential": {
    "environment": "GITHUB_PAT",
    "header": "Authorization",
    "basic_username": "x-access-token"
  }
}
```

`basic_username` constructs HTTP Basic authentication with the environment
credential as its password. It is mutually exclusive with `prefix`. This is
useful when an origin serves both ordinary APIs and Git smart HTTP.

### Routes

Routes may contain one named placeholder. A normal placeholder matches one path
segment:

```text
/v1/models/{model}:generate
```

A placeholder ending in `...` matches one or more characters across path
segments:

```text
/{path...}
```

Matching uses the HTTP method and URL path. Query parameters do not participate
in route matching.

### Backend selection

Limes selects the first available backend for each listener at startup. An `http`
or `https` backend is available when its credential environment variable is
nonempty.

The built-in subscription backends are available when Limes finds valid
credentials from the corresponding official CLI login:

```json
{ "type": "openai_subscription" }
```

`openai_subscription` uses local Codex or ChatGPT subscription credentials.
`xai_subscription` uses the official Grok CLI login from `$GROK_HOME/auth.json`
or `~/.grok/auth.json` and exposes `POST /v1/responses` through xAI's CLI proxy:

```json
{ "type": "xai_subscription" }
```

The xAI backend reads the request's required `model` field to select the upstream
model. Run `grok login` before starting Limes if no Grok login exists.

A listener is disabled when none of its backends are available. Startup fails if
every listener is disabled. Selected backends do not change while Limes is
running.

See [`config.example.json`](config.example.json) for a complete configuration.

## Running as a macOS service

The macOS scripts install Limes as a per-user LaunchAgent. It starts when you log
in, remains running, and restarts after an unexpected exit. Installation does not
require `sudo`.

The installer requires an explicit stable release version, downloads the archive
and `checksums.txt` from GitHub, verifies the SHA-256 checksum, and installs:

- Binary: `~/.local/bin/limes`
- Launcher: `~/.local/libexec/limes/run`
- LaunchAgent: `~/Library/LaunchAgents/com.crowl.limes.plist`
- Logs: `~/Library/Logs/Limes/`
- Configuration: `${XDG_CONFIG_HOME:-$HOME/.config}/limes/config.json`
- Credentials: `${XDG_CONFIG_HOME:-$HOME/.config}/limes/environment`

The release must include the features used by your configuration. In particular,
the `https` backend and CA commands require a release containing those changes.

### Prepare configuration and credentials

Create the configuration before running the installer:

```sh
mkdir -p ~/.config/limes
chmod 700 ~/.config/limes
cp config.example.json ~/.config/limes/config.json
```

Create the credential file without placing secrets in shell history:

```sh
umask 077
cat > ~/.config/limes/environment
```

Enter one `NAME=VALUE` entry per line, then press Control-D:

```text
GITHUB_PAT=github_pat_...
OPENAI_API_KEY=...
```

The format is deliberately not shell syntax:

- Blank lines and lines beginning with `#` are ignored.
- Names must match `[A-Za-z_][A-Za-z0-9_]*`.
- Everything after the first `=` is the literal value.
- Quotes, substitutions, and backslash escapes are not evaluated.

Ensure the credential file is accessible only to your user:

```sh
chmod 600 ~/.config/limes/environment
```

If the configuration enables an `https` backend, initialize the CA using the
release binary after installation, then restart the service:

```sh
~/.local/bin/limes ca init
scripts/macos/restart.sh
```

Only `ca-cert.pem` should be distributed to clients. Never copy `ca-key.pem` or
the environment file into a client.

### Install or upgrade

Run the installer from a checkout and provide an explicit release tag:

```sh
scripts/macos/install.sh v0.3.0
```

Running it again with a newer version upgrades the binary and replaces the
LaunchAgent definition while preserving configuration, credentials, and CA
material.

The installer validates the credential-file permissions and required installation
files before loading the LaunchAgent. If an `https` backend is configured before
its CA is initialized, the service will log a startup error until `limes ca init`
is run.

### Operate the service

```sh
scripts/macos/status.sh
scripts/macos/stop.sh
scripts/macos/start.sh
scripts/macos/restart.sh
tail -f ~/Library/Logs/Limes/stderr.log
```

After changing `config.json` or `environment`, restart Limes to load the new
values:

```sh
scripts/macos/restart.sh
```

### Uninstall

Preserve the installed binary, configuration, credentials, CA, and logs:

```sh
scripts/macos/uninstall.sh
```

Also remove the installed binary:

```sh
scripts/macos/uninstall.sh --purge
```

Configuration, credentials, CA material, and logs are intentionally never
removed automatically.

### Credential-file security

The environment file stores plaintext credentials protected by macOS filesystem
permissions. The launcher rejects symbolic links, files not owned by the current
user, and files readable or writable by group or others. The configuration
directory is created with mode `0700`, and the LaunchAgent applies a restrictive
umask.

Use FileVault to protect credentials while the Mac is powered off. Processes
running as your user may generally access your files and process environment, so
this mechanism is a local operational boundary rather than isolation from other
software already running with your account's authority.

## Development

```sh
gofmt -d .
go mod tidy -diff
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
```
