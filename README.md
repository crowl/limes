# Limes

<p align="center">
  <img src="docs/limes.jpg" alt="Limes" width="600">
</p>

**Limes is a local HTTP proxy that lets sandboxed tools use host-held API
credentials without exposing the secrets.**

```text
sandbox, agent, or container  ->  Limes  ->  API
                                     |
                              injects host credential
```

Point a client at Limes with `HTTP_PROXY` and `HTTPS_PROXY`. For configured
hosts, Limes terminates TLS, checks the request against an allowlist, removes
caller-supplied credentials, injects the credential held by the host, and
forwards the request. The client keeps using the API's real hostname and never
receives the secret.

Limes is useful for coding agents, containers, development tools, automation,
and other local processes that need API access but should not possess API keys,
access tokens, or subscription credentials.

## Quick start

Limes requires Go 1.27.0 when building from source.

```sh
go build -o limes .
mkdir -p ~/.config/limes
cp config.example.json ~/.config/limes/config.json
./limes ca init
./limes ca certificate > limes-ca.pem
./limes
```

Set the credential environment variables referenced by your configuration
before starting Limes. Then configure the client:

```sh
export HTTP_PROXY=http://127.0.0.1:8800
export HTTPS_PROXY=http://127.0.0.1:8800
export SSL_CERT_FILE="$PWD/limes-ca.pem"
```

The client must trust `limes-ca.pem` because Limes terminates TLS for the hosts
it manages. Keep the CA private key on the host.

## Minimal configuration

This rule allows `POST /v1/responses` on `api.openai.com` and replaces any
caller-provided authorization with `OPENAI_API_KEY` from the Limes environment:

```json
{
  "proxy": {
    "address": "127.0.0.1:8800",
    "rules": [
      {
        "name": "openai",
        "backends": [
          {
            "type": "http",
            "upstreams": ["https://api.openai.com"],
            "routes": [
              { "method": "POST", "path": "/v1/responses" }
            ],
            "remove_headers": ["Authorization"],
            "credential": {
              "environment": "OPENAI_API_KEY",
              "header": "Authorization",
              "prefix": "Bearer "
            }
          }
        ]
      }
    ]
  }
}
```

A rule claims the hostnames in its backends. Requests to a claimed host that do
not match an allowed route receive `403` and are never relayed.

Destinations not claimed by a rule are relayed unchanged by default. Set
`"unclaimed": "deny"` on the proxy to make it an egress allowlist. Limes always
refuses to relay to loopback, private, link-local, and multicast addresses.

See [`config.example.json`](config.example.json) for OpenAI, Anthropic, xAI,
Gemini, and GitHub examples, and [Configuration](docs/configuration.md) for the
complete reference.

## Subscription backends

Limes can use credentials from official CLI logins instead of API keys:

```json
{ "type": "openai_subscription" }
{ "type": "anthropic_subscription" }
{ "type": "xai_subscription" }
```

A rule can list several backends. Limes selects the first one whose credentials
are available, so a subscription backend can precede an API-key fallback. See
the complete examples in [`config.example.json`](config.example.json).
Subscription backends read local Codex/ChatGPT, Claude Code, or Grok CLI login
credentials. They use consumer subscription authority rather than API billing.
See [Configuration](docs/configuration.md#subscription-backends) for credential
locations and supported routes.

## Containers

Mount the public CA certificate and point the container at the host proxy:

```sh
docker run --rm -it \
  -e HTTP_PROXY=http://host.docker.internal:8800 \
  -e HTTPS_PROXY=http://host.docker.internal:8800 \
  -e SSL_CERT_FILE=/etc/limes/limes-ca.pem \
  -v "$PWD/limes-ca.pem:/etc/limes/limes-ca.pem:ro" \
  my-image
```

## Admin panel

Enable the local admin panel to inspect rules, switch between available
backends, and view the latest 200 completed requests:

```json
{
  "admin": { "address": "127.0.0.1:8799" },
  "proxy": { "...": "..." }
}
```

Open `http://127.0.0.1:8799/`. The panel never displays credentials or stores
request bodies, headers, query parameters, or client addresses.

## Security

Limes protects credentials, not the authority they grant. Any client that can
reach Limes can perform operations allowed by its configured routes. Use narrow
routes and narrowly scoped credentials.

Limes does not authenticate clients. Bind it to loopback unless a VM or
container must reach it, and use host firewall or virtualization boundaries when
binding beyond loopback. Never expose it to an untrusted network.

Requests and responses are streamed without automatic retries. Intercepted
connections use HTTP/1.1; gRPC and other clients that require HTTP/2 are not
supported for claimed hosts.

Read the full [security model and CA guide](docs/security.md).

## More documentation

- [Configuration reference](docs/configuration.md)
- [Security model and certificate authority](docs/security.md)
- [Running as a macOS service](docs/macos.md)

## Development

```sh
gofmt -d .
go mod tidy -diff
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
```
