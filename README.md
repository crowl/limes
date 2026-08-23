# Limes

<p align="center">
  <img src="docs/limes.jpg" alt="Limes" width="600">
</p>

Limes is a local HTTP proxy that keeps LLM provider credentials outside sandboxed coding agents and other client applications.

A sandbox can be configured to send provider requests to a Limes listener using placeholder credentials. Limes validates each request, removes caller-provided credentials, injects the real host-side credential, and forwards the request to the provider. This lets coding agents use LLM APIs without copying API keys or subscription credentials into the sandbox.

Requests and responses are streamed without automatic retries.

Limes does not authenticate incoming clients. Prefer loopback listener addresses and do not expose it to untrusted networks.

## Setup

Limes requires Go 1.27.0.

```sh
go build -o limes .
mkdir -p ~/.config/limes
cp config.example.json ~/.config/limes/config.json
./limes
```

Set the environment variables referenced by your configuration before starting Limes.

To use another configuration file:

```sh
./limes --config-path ./config.json
```

Without `--config-path`, Limes looks in:

1. `$XDG_CONFIG_HOME/limes/config.json`
2. `$HOME/.config/limes/config.json`

## Configuration

A configuration defines one or more listeners and an ordered list of backend candidates for each listener:

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
            {
              "method": "POST",
              "path": "/v1/messages"
            }
          ],
          "remove_headers": [
            "Authorization"
          ],
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

The generic `http` backend:

- Forwards only configured method and path combinations
- Removes configured headers and query parameters
- Replaces the configured credential header
- Reads the credential from a host environment variable
- Supports upstream path prefixes
- Streams upstream responses

Routes may contain one named, single-segment placeholder:

```text
/v1/models/{model}:generate
```

Configure the sandboxed client with the listener URL as its provider base URL and any nonempty placeholder credential it requires. The real credential remains in Limes' host environment.

## Backend selection

Limes selects the first available backend for each listener at startup.

An `http` backend is available when its credential environment variable is nonempty. The built-in `openai_subscription` backend is available when Limes finds valid local Codex or ChatGPT subscription credentials:

```json
{
  "type": "openai_subscription"
}
```

A listener is disabled when none of its backends are available. Startup fails if every listener is disabled. Selected backends do not change while Limes is running.

See [`config.example.json`](config.example.json) for a complete configuration.

## Development

```sh
gofmt -d .
go mod tidy -diff
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
```
