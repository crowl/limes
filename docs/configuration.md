# Configuration

Limes reads strict JSON from:

1. the path passed with `--config-path`;
2. `$XDG_CONFIG_HOME/limes/config.json`; or
3. `$HOME/.config/limes/config.json`.

Unknown fields, duplicate object keys, and invalid values cause startup to fail.
A configuration requires one `proxy` and may enable the local admin panel:

```json
{
  "admin": { "address": "127.0.0.1:8799" },
  "proxy": {
    "address": "127.0.0.1:8800",
    "unclaimed": "relay",
    "rules": [
      {
        "name": "openai",
        "backends": [{ "type": "openai_subscription" }]
      }
    ]
  }
}
```

See [`config.example.json`](../config.example.json) for a complete example.

## Proxy

`proxy.address` is the HTTP proxy address given to clients through `HTTP_PROXY`
and `HTTPS_PROXY`.

`proxy.unclaimed` controls destinations that no rule claims:

- `relay` is the default and forwards unclaimed destinations unchanged and
  uninspected.
- `deny` rejects unclaimed destinations, making Limes an egress allowlist.

Both policies refuse non-public destinations.

Each rule has a unique `name` and an ordered list of `backends`. Limes selects
the first available backend at startup. If none is available, the rule still
claims its hosts but responds with `503`; it never falls back to relaying a
claimed host.

Two rules may not claim the same hostname.

## HTTP backend

The `http` backend forwards allowed requests with a host-held credential:

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
  "remove_query_parameters": ["token"],
  "credential": {
    "environment": "GITHUB_PAT",
    "header": "Authorization",
    "basic_username": "x-access-token"
  }
}
```

Fields:

- `upstreams`: absolute HTTP or HTTPS URLs. Their DNS hostnames are claimed by
  the rule. IP addresses are not accepted because Limes issues TLS certificates
  for claimed names. Several upstreams may be listed; the requested hostname
  selects one.
- `routes`: allowed method and path combinations.
- `remove_headers`: headers removed before forwarding. Limes always replaces
  the configured credential header.
- `remove_query_parameters`: query parameters removed before forwarding.
- `credential.environment`: environment variable containing the secret.
- `credential.header`: upstream authentication header.
- `credential.prefix`: optional text prepended to the secret, such as
  `"Bearer "`.
- `credential.basic_username`: constructs HTTP Basic authentication using this
  username and the environment credential as the password. It is mutually
  exclusive with `prefix`.

Requests and responses are streamed without automatic retries.

## Routes

Routes match the HTTP method and URL path. Query parameters are not part of
matching. Methods are normalized to uppercase.

An exact path matches only itself:

```json
{ "method": "POST", "path": "/v1/responses" }
```

A named placeholder matches one non-empty path segment:

```text
/v1/models/{model}:generate
```

A placeholder ending in `...` matches non-empty text across path segments:

```text
/{path...}
```

## Subscription backends

Subscription backends claim a provider's public API hostname and use credentials
from its official CLI login. They accept no additional configuration fields.

### OpenAI

```json
{ "type": "openai_subscription" }
```

Claims `api.openai.com` and uses local Codex or ChatGPT subscription
credentials.

### Anthropic

```json
{ "type": "anthropic_subscription" }
```

Claims `api.anthropic.com` and exposes `POST /v1/messages` using Claude Code
credentials. On macOS, Limes first reads the `Claude Code-credentials` Keychain
item. Otherwise it reads `$CLAUDE_CONFIG_DIR/.credentials.json` or
`~/.claude/.credentials.json`. Run `claude` and complete login first.

Limes refreshes expiring OAuth credentials and writes them back to their source.
The integration relies on Claude Code's consumer OAuth protocol and may need
updates when that protocol changes.

### xAI

```json
{ "type": "xai_subscription" }
```

Claims `api.x.ai` and exposes `POST /v1/responses` through xAI's CLI proxy. It
reads `$GROK_HOME/auth.json` or `~/.grok/auth.json`. Run `grok login` first.

## Admin panel

The optional admin panel must bind to `localhost` or a loopback IP and cannot
share the proxy address:

```json
{ "admin": { "address": "127.0.0.1:8799" } }
```

It shows each rule's available backends and allows switching the backend used by
new requests. In-flight requests remain on the backend that accepted them.
Selections are held in memory and reset to the first available backend after a
restart.

The request log stores the latest 200 completed requests in memory. Claimed
requests are associated with their rule. Relayed connections are shown as
`CONNECT` requests under `proxy`, without visibility into their contents.
