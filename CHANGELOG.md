# Change log

All notable changes to the 2FA-Vault CLI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-10-09

### Added

- **Local E2EE vault support** (CLI Phase 2): `get` / `copy` now decrypt E2EE
  accounts locally — Argon2id key derivation (hash-wasm) + AES-256-GCM, byte-identical
  with the web app — and compute TOTP/HOTP/Steam OTPs on the machine. The
  master password is used once at unlock and never stored or sent.
- `--remember[=<hours>]` on `get` / `copy`: opt-in derived-key cache in the OS
  keychain (default 8h TTL, keyed by host + salt, never the password, re-verified
  against the vault test value on every run, purged on failure/expiry/logout).
- `2fav list` marks E2EE accounts with a 🔒 glyph.
- Local Argon2id/AES/OTP crypto engine (`services/crypto.ts`, `services/otp.ts`)
  with cross-implementation parity fixtures: argon2 raw hashes + AES envelopes
  captured in chromium against the real argon2-browser WASM, OTP vectors from
  the PHP server stack (otphp + steam-totp), and RFC 6238 known answers.
- `crypto-gate` GitHub Actions workflow: on ubuntu it runs the full suite,
  compiles the CLI + a deriveKey probe and executes both, proving the WASM
  works in the compiled binary (RT-14 gate).

### Changed

- E2EE detection in `get`/`copy` no longer fails fast: E2EE accounts take the
  local decrypt path (the old server-cannot-decrypt error remains for
  team-shared E2EE accounts, which cannot be unwrapped locally).
- HOTP generation syncs the server counter via `PATCH /twofaccounts/{id}/counter`
  and adopts the server counter once on a non-monotonic (422) rejection.
- Unlock attests via `POST /encryption/verify` at most once per cache lifetime;
  a 429 (shared per-IP budget) or network error is skipped silently.
- A failed vault verification now answers with a vault-specific message instead
  of the generic "PAT may be invalid" hint.
- `2fav login` prompt logic shared with the vault unlock prompt (muted echo on
  TTY, piped-stdin fallback).

### Fixed

- `get --watch` without `--remember` re-prompted the master password at every
  TOTP period and hit `/encryption/info` each iteration — the key is now
  derived once and the watch loop is fully offline.
- A corrupted keychain entry no longer crashes the unlock path; it is purged
  and the flow degrades to a fresh password prompt.
- An account with an unrecognized `otp_type` fails closed with a named error
  instead of silently computing a wrong TOTP.
- `list` degrades to a glyph-less listing when the E2EE endpoint fails instead
  of hard-failing.
- One-shot `get`/`copy` scrub the derived key bytes after use.

### CI

- The release workflow now consumes the crypto runtime gate as a required job —
  a tag cannot ship without the executed-binary parity proof.
- `bun run typecheck` (now clean repo-wide) gates both the crypto gate and the
  release build.

## [0.2.0] - 2026-08-08

### Added

- `2fav list --search <text>`: alias for `--filter` (case-insensitive substring match on service/account).
- `2fav get <service> --watch`: refreshes the OTP at the start of each TOTP period until interrupted (disabled with a note for HOTP/period-less accounts).
- `2fav get <service> --copy`: additionally copies the OTP to the system clipboard.
- E2EE detection in `get`: emits a clear, actionable error when the target account uses E2EE (CLI v1 supports non-E2EE vaults only), instead of failing opaquely.
- `bun run test` npm/bun script; the release workflow can now gate on it.

### Security

- `2fav login` no longer silently falls back to plaintext PAT storage when keytar cannot load (common with cross-compiled binaries on Linux ARM or headless hosts). It now refuses to persist and requires explicit `--insecure-store` to opt in to the `0600` plaintext fallback.

### Changed

- The compiled binary's `--version` is now read from `package.json` instead of a hardcoded literal, so the two can never drift.

### Tests

- 7 new command-level tests (findUniqueAccount no-match/unique/ambiguous, whitespace trimming, null-service, E2EE shape); 36 tests now pass.

## [1.0.0] - 2026-06-14

Phase 1 MVP. API-only commands (no E2EE); OTPs are generated server-side.

### Added

- `2fav login --host <URL>`: prompts for a Personal Access Token (PAT), verifies it against `GET /api/v1/user`, and stores host + PAT in the OS keychain.
- `2fav logout`: removes stored credentials from the keychain (and the fallback file).
- `2fav list [--filter <text>]`: lists accounts as `[id] service — account`, with optional case-insensitive substring filter.
- `2fav get <service>`: prints the current one-time password for the matching account.
- `2fav copy <service>`: copies the current one-time password to the system clipboard.
- `2fav --version` / `2fav --help`: standard help and version output.
- Single-binary distribution via `bun build --compile` (Linux x64/arm64, macOS x64/arm64, Windows x64).
- OS keychain storage via `keytar` (macOS Keychain / Windows Credential Manager / libsecret on Linux), with a `0600` plaintext fallback at `~/.2fav/config.json` when no secret service is available.

### Security

- The PAT is stored in the OS keychain and never written to disk unencrypted unless the keychain is unavailable, in which case the fallback file is created with mode `0600` and a warning is printed.
- Phase 1 generates OTPs server-side; for an E2EE-enabled vault the server holds an opaque encrypted payload and cannot generate OTPs. Local vault unlock + client-side TOTP lands in Phase 2.
- No telemetry, no analytics.

### Notes

- Phase 2 (local E2EE unlock with Argon2id + AES-256-GCM mirroring `2FA-Vault/resources/js/services/crypto.js`, and client-side TOTP) is not yet implemented.
- Tests: 29 unit tests (api, keychain, clipboard) pass under `bun test`.
