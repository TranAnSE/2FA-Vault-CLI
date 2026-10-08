# 2FA-Vault CLI

A command-line client for [2FA-Vault](../2FA-Vault). Manage your two-factor
authentication accounts from the terminal — list accounts, fetch a one-time
password, copy it to the clipboard.

This is the **Phase 1 MVP**: API-only commands. End-to-end-encryption (local
vault unlock and client-side TOTP) lands in Phase 2.

- **Runtime:** [Bun](https://bun.sh) (TypeScript)
- **Single binary:** `bun build --compile` produces a standalone executable per platform
- **Secure storage:** PAT stored in the OS keychain (macOS Keychain / Windows Credential Manager / libsecret on Linux), with a plaintext fallback (`~/.2fav/config.json`, mode `0600`) when the keychain is unavailable

## Install

### From a release binary

Download the binary for your platform from the latest
[GitHub Release](../../releases) and put it on your `PATH`. Rename it to `2fav`
(or `2fav.exe` on Windows).

### From source

```bash
git clone <repo-url> 2FA-Vault-CLI
cd 2FA-Vault-CLI
bun install
bun run build           # produces dist/2fav
```

For cross-compiled binaries (no local toolchain needed):

```bash
bun run build:linux-x64
bun run build:darwin-arm64
bun run build:win-x64
# (see package.json for all targets)
```

### Prerequisites

- A running 2FA-Vault instance
- A **Personal Access Token (PAT)** with access to the `twofaccounts` scope.
  Create one from your 2FA-Vault user settings.
- On Linux, the OS keychain requires a running secret service
  (`gnome-keyring`, `KWallet`, or `keepassxc`). Without one, the CLI falls back
  to the plaintext config file and prints a warning.
- The `copy` command needs a clipboard helper: `pbcopy` (macOS), `clip.exe`
  (Windows), or `xclip` / `xsel` / `wl-copy` (Linux).

## Usage

```bash
2fav login --host https://vault.example.com
# Personal Access Token: ********
# Logged in to https://vault.example.com. Credentials stored in the OS keychain.

2fav list
# [1] GitHub — alice@example.com
# [2] GitLab — alice
# 2 accounts.

2fav list --filter git
2fav get github
# 045698

2fav copy github
# OTP copied to clipboard for GitHub.

2fav get github --watch
# 045698
# (re-prints the code every TOTP period — TOTP only, ignored for HOTP)

2fav get github --copy
# 045698
# OTP copied to clipboard for GitHub.

2fav logout
# Logged out. Stored credentials removed.
```

## Commands

| Command | Description |
| --- | --- |
| `2fav login --host <URL>` | Prompt for a PAT, verify it, and store host + PAT in the OS keychain (plaintext fallback otherwise). |
| `2fav logout` | Remove stored credentials from the keychain and the fallback file. |
| `2fav list [--filter <text>] [--search <text>]` | List accounts as `[id] service — account` (E2EE accounts carry a 🔒 glyph). `--filter` / `--search` are aliases: case-insensitive substring match on service or account. |
| `2fav get <service> [--watch] [--copy] [--remember[=<hours>]]` | Print the current one-time password for the matching account — locally for E2EE accounts (see "E2EE vaults"), server-side otherwise. `--watch` re-prints the code each TOTP period (TOTP only). `--copy` also copies it to the clipboard. `--remember` caches the derived key in the OS keychain (default TTL 8h). |
| `2fav copy <service> [--remember[=<hours>]]` | Copy the current one-time password to the system clipboard (local path for E2EE accounts). |
| `2fav --version` / `2fav --help` | Standard help and version output. |

`<service>` matches case-insensitively as a substring of either the service or
the account label. If more than one account matches, the CLI lists the matches
and asks you to be more specific — it never silently picks one.

Accounts in a non-E2EE vault are generated server-side (`GET …/otp`). Accounts
in an E2EE vault are marked with a 🔒 glyph in `list` and take the local path
described below.

## E2EE vaults (local unlock)

When your vault uses end-to-end encryption, `2fav get` / `2fav copy` decrypt
and compute OTPs **entirely on your machine** — the same way the web app does
(Argon2id key derivation + AES-256-GCM). The master password never leaves the
process, and the server never sees key material.

```bash
2fav get GitHub
# Master password: ********
# 045698

2fav get GitHub --remember          # cache the derived key for 8h (default)
2fav get GitHub --remember=1        # custom TTL in hours
```

- **Unlock** fetches the salt + sealed test value from
  `GET /encryption/info`, derives the key locally and verifies it against the
  test value — a wrong password never reaches the server.
- **`--remember`** caches the **derived key only** (never the password) in the
  OS keychain, keyed by host + salt, with a TTL (default 8 hours). A cached key
  is re-verified against the test value on every run and purged when it fails
  or expires. If the OS keychain is unavailable, the cache is skipped with a
  warning — key material is never written to the plaintext fallback file.
  `2fav logout` removes every cached key.
- **HOTP** accounts advance the server counter after each generation
  (`PATCH /twofaccounts/{id}/counter`). If another device already advanced it,
  the CLI adopts the server counter once; after a second conflict it asks you
  to resynchronize from the web app.
- **Steam (steamtotp)** accounts are computed locally, byte-identical with the
  server's implementation (cross-validated test vectors in the repo).
- **Team-shared E2EE accounts** are not supported: their secrets are sealed
  for another member's key and cannot be unwrapped locally — the CLI fails
  with a pointer to the web app / browser extension.

## API contract

The CLI talks to the standard 2FA-Vault REST API (see
[`2FA-Vault-API`](../2FA-Vault-API)):

- `GET /api/v1/user` — verifies the PAT during `login`.
- `GET /api/v1/twofaccounts` — lists accounts (`{ data: [ { id, service, account, ... } ] }`).
- `GET /api/v1/twofaccounts/encrypted` — lists E2EE accounts with their ciphertext envelopes.
- `GET /api/v1/twofaccounts/{id}/otp` — returns `{ password, otp_type, generated_at, ... }` (non-E2EE accounts).
- `GET /api/v1/encryption/info` — salt + sealed test value for the local unlock.
- `POST /api/v1/encryption/verify` — best-effort unlock attestation (sent at most once per cache lifetime; 429s are skipped silently — the 5/min limit is per IP and shared with other users).
- `PATCH /api/v1/twofaccounts/{id}/counter` — HOTP counter write-back (server requires a strictly greater counter).

All requests send `Authorization: Bearer <PAT>` and `Accept: application/json`.

## Security notes

- The PAT is stored in the OS keychain and never written to disk unencrypted
  by default.
- If the OS keychain is unavailable (keytar cannot load — common with
  cross-compiled binaries on Linux ARM, or headless hosts without a secret
  service), `login` **refuses to silently degrade**. Re-run with
  `--insecure-store` to opt in to the plaintext fallback file
  (`~/.2fav/config.json`, mode `0600`); the CLI prints a warning and a hint
  on how to fix the keychain binding.
- E2EE vaults are unlocked locally: the master password is used once to derive
  the AES key (Argon2id) and then discarded. With `--remember`, only the
  **derived key** is cached — in the OS keychain only, salt-keyed, always with
  a TTL — never the password, and never in the plaintext fallback file.
- OTPs for E2EE accounts are computed locally from cross-validated parity
  vectors (browser argon2 + PHP server stack + RFC 6238 known answers, see
  `src/fixtures/`); non-E2EE OTPs remain server-side.
- No telemetry, no analytics.

## License

MIT.
