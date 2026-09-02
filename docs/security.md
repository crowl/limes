# Security and certificate authority

## Security model

Limes keeps API keys, access tokens, and subscription credentials out of its
clients. It does not limit what a reachable client can do within the routes and
credential authority you configure.

Use narrowly scoped credentials and allow only required methods and paths.
Caller-provided credential headers are removed or replaced before forwarding.
Limes does not retry requests, so it does not duplicate non-idempotent
operations.

Limes does not authenticate incoming clients. Bind the proxy to loopback unless
it must be reached from a local VM or container. When binding beyond loopback,
use firewall and virtualization boundaries and do not expose Limes to untrusted
networks.

## Claimed and unclaimed hosts

For claimed hosts, Limes terminates TLS, validates the route, injects a
credential, and connects independently to the configured upstream. A request to
a claimed host that does not match a route is rejected rather than relayed.
Claimed hosts are intercepted only through `CONNECT` on port 443; plain HTTP and
other ports are rejected.

Unclaimed destinations are either relayed unchanged or denied according to the
proxy configuration. Relaying is not an egress allowlist. It allows the client
to reach public internet destinations without inspection or credentials.

Limes refuses to relay to loopback, private, link-local, unspecified, and
multicast addresses. The check runs after DNS resolution and before connecting
to prevent hostnames from resolving into the local network.

## Certificate authority

Initialize the local CA before starting Limes:

```sh
limes ca init
limes ca status
limes ca certificate > limes-ca.pem
```

Install or mount only `limes-ca.pem` in clients. The private key remains in the
Limes configuration directory and must never be distributed.

The CA can issue certificates for every host claimed by Limes. Trust it only in
clients where Limes interception is intended.

Rotate the CA explicitly:

```sh
limes ca rotate --force
```

Clients trusting the previous certificate must be updated after rotation.

Intercepted connections negotiate HTTP/1.1. Clients requiring HTTP/2 for a
claimed host, including gRPC clients, are not supported. Opaque relayed
connections are unaffected.

## Admin panel and logs

The admin panel is restricted to loopback addresses and uses browser security
headers, same-origin checks, and a per-process form token. It does not provide
client authentication and should not be exposed through another server or
reverse proxy.

The in-memory request log records rule, backend, method, path, status, duration,
and completion time. It does not retain request bodies, headers, query
parameters, credentials, or client addresses. Relayed TLS content is opaque to
Limes. The log is cleared at restart.
