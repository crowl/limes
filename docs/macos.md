# Running Limes as a macOS service

The macOS scripts install Limes as a per-user LaunchAgent. It starts at login,
restarts after an unexpected exit, and does not require `sudo`.

The installer downloads a specified stable release and its checksums, verifies
the archive, and installs:

- Binary: `~/.local/bin/limes`
- Launcher: `~/.local/libexec/limes/run`
- LaunchAgent: `~/Library/LaunchAgents/com.crowl.limes.plist`
- Logs: `~/Library/Logs/Limes/`
- Configuration: `${XDG_CONFIG_HOME:-$HOME/.config}/limes/config.json`
- Credentials: `${XDG_CONFIG_HOME:-$HOME/.config}/limes/environment`

## Prepare configuration and credentials

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

Enter one `NAME=VALUE` per line and press Control-D. For example:

```text
GITHUB_PAT=github_pat_...
OPENAI_API_KEY=...
```

The file is deliberately not shell syntax:

- Blank lines and lines beginning with `#` are ignored.
- Names must match `[A-Za-z_][A-Za-z0-9_]*`.
- Everything after the first `=` is the literal value.
- Quotes, substitutions, and backslash escapes are not evaluated.

```sh
chmod 600 ~/.config/limes/environment
```

## Install or upgrade

Run the installer from a checkout with a release tag:

```sh
scripts/macos/install.sh v0.6.0
```

Running it again with a newer version upgrades the binary while preserving
configuration, credentials, CA material, and logs.

Initialize the CA after installation and restart the service:

```sh
~/.local/bin/limes ca init
scripts/macos/restart.sh
```

Export the public certificate for clients when needed:

```sh
~/.local/bin/limes ca certificate > limes-ca.pem
```

Never copy `ca-key.pem` or the environment file into a client.

## Operate the service

```sh
scripts/macos/status.sh
scripts/macos/stop.sh
scripts/macos/start.sh
scripts/macos/restart.sh
tail -f ~/Library/Logs/Limes/stderr.log
```

Restart after changing `config.json` or `environment`.

## Uninstall

Preserve the binary, configuration, credentials, CA, and logs:

```sh
scripts/macos/uninstall.sh
```

Also remove the binary:

```sh
scripts/macos/uninstall.sh --purge
```

Configuration, credentials, CA material, and logs are never removed
automatically.

## Credential-file security

The launcher rejects symbolic links, files not owned by the current user, and
files readable or writable by group or others. It applies a restrictive umask.
Use FileVault to protect credentials while the Mac is powered off.

Processes running as your user can generally access your files and environment,
so this is an operational boundary for sandboxed clients, not isolation from
other software already running with your account's authority.
