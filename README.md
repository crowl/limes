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

Limes works two ways. A **listener** gives one provider its own local address,
and the client is configured with that address as its base URL. A **proxy**
gives a client a single `HTTPS_PROXY` endpoint, claims the hosts named by its
rules, and relays every other destination to its real origin. Proxy mode suits
containers, which can then run unmodified tools against real provider hostnames
without holding any credential.

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

Listeners and claimed proxy hosts accept only configured routes and upstreams.
Caller-provided credential headers are always replaced. Limes does not retry
requests, so it does not duplicate non-idempotent operations.

Proxy mode is not an egress allowlist. A destination no rule claims is relayed
to its real origin unmodified, uninspected, and without credentials, so a client
using Limes as its proxy reaches the internet as it otherwise would. Limes only
refuses to relay to non-public addresses: loopback, private, link-local, and
multicast destinations are rejected after resolution, which keeps a client from
using Limes to reach the host itself or the surrounding private network.

## Installation

Limes requires Go 1.27.0 when building from source:

```sh
go build -o limes .
./limes -version
mkdir -p ~/.config/limes
cp config.example.json ~/.config/limes/config.json
./limes ca init
./limes
```

Set the environment variables referenced by the configuration before starting
Limes.

The example configuration defines a proxy, which terminates TLS for the hosts it
claims, so `limes ca init` must run before the first start. Clients then need the
public certificate:

```sh
./limes ca certificate > limes-ca.pem
```

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
  "proxy": {
    "...": "..."
  }
}
```

Open `http://127.0.0.1:8799/` to inspect listeners and proxy rules and switch
between their available backends without restarting Limes. Open
`http://127.0.0.1:8799/requests` to view the request log. Requests to a claimed
host are recorded under their rule name; relayed connections are recorded as
`CONNECT` to the destination authority, without any view of their contents.
Switching affects new requests; in-flight requests finish on the backend that
accepted them. The
selection is held only in memory, so restarting Limes restores the first
available backend in configuration order. The panel keeps the latest 200
completed requests in memory and shows their listener, backend, method, path,
status, and duration. Request bodies, headers, query parameters, credentials,
and client addresses are not retained. The request log is cleared when Limes
restarts.

The admin panel is disabled when `admin` is omitted. Its address must use
`localhost` or a loopback IP and cannot match a proxy listener address. It shows
sanitized availability information and never displays credentials. Backend
availability is evaluated during startup; restart Limes after adding or fixing a
credential.

If a listener has no available backend, it is not bound but remains visible in
the admin panel. Limes can run with only the admin panel when every backend is
unavailable. Without an enabled admin panel, Limes exits when no backend is
available.

A configuration defines a `proxy`, one or more `listeners`, or both. Each proxy
rule and each listener holds an ordered list of backend candidates, and the
first available candidate is active at startup.

[`config.example.json`](config.example.json) configures a proxy, which is the
usual choice: a client gets one endpoint, keeps using real provider hostnames,
and needs no per-service configuration. Listeners suit clients that cannot use a
proxy or cannot be given a CA certificate, since an `http` listener needs
neither.

### Proxy

A `proxy` block binds one address that serves as a client's HTTP and HTTPS
proxy. Each rule claims one or more hosts and holds an ordered list of backend
candidates for them:

```json
{
  "proxy": {
    "address": "0.0.0.0:8800",
    "rules": [
      {
        "name": "openai",
        "backends": [
          { "type": "openai_subscription" },
          {
            "type": "http",
            "upstreams": ["https://api.openai.com"],
            "routes": [{ "method": "POST", "path": "/v1/responses" }],
            "remove_headers": ["Authorization"],
            "credential": {
              "environment": "OPENAI_API_KEY",
              "header": "Authorization",
              "prefix": "Bearer "
            }
          }
        ]
      },
      {
        "name": "github",
        "backends": [
          {
            "type": "http",
            "upstreams": ["https://github.com", "https://api.github.com"],
            "routes": [{ "method": "GET", "path": "/{path...}" }],
            "remove_headers": ["Authorization"],
            "credential": {
              "environment": "GITHUB_PAT",
              "header": "Authorization",
              "basic_username": "x-access-token"
            }
          }
        ]
      }
    ]
  }
}
```

A backend claims the hosts a client addresses to reach it:

| Backend                  | Claimed hosts         |
| ------------------------ | --------------------- |
| `http`                   | each `upstreams` host |
| `openai_subscription`    | `api.openai.com`      |
| `anthropic_subscription` | `api.anthropic.com`   |
| `xai_subscription`       | `api.x.ai`            |

A subscription backend claims the provider's public API host but serves the
request from local subscription credentials, so a client configured for
`https://api.openai.com` reaches ChatGPT subscription authority without
knowing it. Two rules may not claim the same host; Limes refuses to start when
they do.

A proxy requires the CA, because claiming a host means terminating its TLS.
Run `limes ca init` before starting Limes with a `proxy` block.

`unclaimed` decides what happens to destinations no rule claims:

```json
{ "proxy": { "address": "0.0.0.0:8800", "unclaimed": "deny", "rules": [] } }
```

`relay`, the default, forwards them to their real origin unmodified. `deny`
rejects them, which turns the proxy into an egress allowlist for clients that
should reach nothing but the configured hosts. Both refuse non-public
destinations.

Requests to a claimed host follow the rule's routes and credential exactly as a
listener would. Because a host is claimed before any request is visible, a
claimed host that a rule's routes do not allow is rejected with `403` rather
than relayed. Claimed hosts are served only over `CONNECT` to port 443;
plain-HTTP requests to a claimed host are rejected so a client cannot bypass
interception by downgrading.

Intercepted connections negotiate HTTP/1.1. Clients requiring HTTP/2 to a
claimed host, such as gRPC, are not supported. Relayed connections are opaque
and unaffected.

Point a container at the proxy and give it the CA certificate:

```sh
limes ca certificate > limes-ca.pem
docker run --rm -it \
  -e HTTPS_PROXY=http://host.docker.internal:8800 \
  -e HTTP_PROXY=http://host.docker.internal:8800 \
  -e SSL_CERT_FILE=/etc/limes/limes-ca.pem \
  -v "$PWD/limes-ca.pem:/etc/limes/limes-ca.pem:ro" \
  my-image
```

A proxy and per-provider listeners may both be configured. Their addresses and
names must differ.

### Listeners

A listener gives one provider its own address, and the client uses that address
as its base URL:

```json
{
  "listeners": [
    {
      "name": "example",
      "address": "127.0.0.1:8787",
      "backends": [
        {
          "type": "http",
          "upstreams": ["https://api.example.com"],
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

The generic `http` backend is the only configurable backend. It:

- Forwards only configured method and path combinations
- Removes configured headers and query parameters
- Replaces the configured credential header
- Reads the credential from a host environment variable
- Supports upstream path prefixes
- Streams upstream responses

It takes one or more `upstreams`. A proxy rule may list several, because the
host a client addresses selects among them:

```json
{
  "type": "http",
  "upstreams": [
    "https://github.com",
    "https://api.github.com"
  ],
  "routes": [
    { "method": "GET", "path": "/{path...}" },
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

A listener backend accepts exactly one upstream, since a client addresses the
listener rather than the upstream host and there is nothing to select among.

Upstreams reached through a listener may be any absolute `http` or `https` URL,
including IP addresses, explicit ports, and path prefixes. An upstream claimed
by a proxy rule must use a DNS hostname, because the proxy issues a certificate
for the host it claims.

`basic_username` constructs HTTP Basic authentication with the environment
credential as its password. It is mutually exclusive with `prefix`. This is
useful when an origin serves both ordinary APIs and Git smart HTTP.

Configure a client with the listener URL, or with the proxy and the real
upstream hostname, and any nonempty placeholder credential it requires. The real
credential remains in the Limes process environment.

### Certificate authority

A proxy terminates TLS for the hosts it claims, so it needs a local CA:

```sh
limes ca init
limes ca status
limes ca certificate > limes-ca.pem
```

The CA private key remains in the Limes configuration directory. Install or mount
only the public certificate in clients that use the proxy. The CA can issue a
certificate for any host Limes claims, so clients should trust it only where
interception by Limes is intended.

Rotate the CA explicitly when needed:

```sh
limes ca rotate --force
```

Clients trusting the previous CA must be updated after rotation.

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

Limes selects the first available backend for each listener and proxy rule at
startup. An `http` backend is available when its credential
environment variable is nonempty. A proxy rule with no available backend rejects
requests to the hosts it claims; it does not fall back to relaying them.

The built-in subscription backends are available when Limes finds valid
credentials from the corresponding official CLI login. They use consumer
subscription authority rather than API billing and accept no additional
configuration fields.

`anthropic_subscription` uses the official Claude Code login and exposes the
native Anthropic Messages endpoint at `POST /v1/messages`:

```json
{ "type": "anthropic_subscription" }
```

On macOS it first reads the `Claude Code-credentials` Keychain item. If that item
is unavailable, and on other platforms, it reads
`$CLAUDE_CONFIG_DIR/.credentials.json` or `~/.claude/.credentials.json`. Run
`claude` and complete its login before starting Limes. Limes refreshes expiring
OAuth credentials and writes them back to the store from which they were read.
It preserves the caller's native Messages fields and model, adds the Claude Code
request attribution required by Anthropic's subscription endpoint, and supports
streaming responses. It does not expose `/v1/messages/count_tokens`.

`openai_subscription` uses local Codex or ChatGPT subscription credentials:

```json
{ "type": "openai_subscription" }
```

`xai_subscription` uses the official Grok CLI login from `$GROK_HOME/auth.json`
or `~/.grok/auth.json` and exposes `POST /v1/responses` through xAI's CLI proxy:

```json
{ "type": "xai_subscription" }
```

The xAI backend reads the request's required `model` field to select the upstream
model. Run `grok login` before starting Limes if no Grok login exists.

The Anthropic subscription integration relies on Claude Code's consumer OAuth
protocol and credential format. These are maintained by Anthropic's official
client but are less stable than its public API-key contract and may require Limes
updates when Claude Code changes.

A listener is disabled when none of its backends are available. Startup fails if
every listener is disabled and no proxy or admin panel is configured. A proxy is
bound whenever it is configured, because it relays unclaimed destinations even
when no rule has credentials.

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
the proxy and CA commands require a release containing those changes.

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

If the configuration defines a proxy, initialize the CA using the release binary
after installation, then restart the service:

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
files before loading the LaunchAgent. If a proxy is configured before its CA is
initialized, the service will fail to start until `limes ca init` is run.

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
