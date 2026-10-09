/**
 * Vault unlock + local OTP orchestration for E2EE accounts (CLI phase 2).
 *
 * Unlock is fully local: `GET /encryption/info` provides the salt + sealed
 * test value; the master password derives the AES key (Argon2id) and a
 * successful local decryption of the test value proves the password. The
 * server never sees either. `POST /encryption/verify` is only a cross-device
 * lock-state attestation (client-attested by design, A4) — sent at most once
 * per cache lifetime, never on cache hits, and a 429 (the per-IP budget is
 * shared with other users, RT-12) or network hiccup is skipped silently.
 *
 * The `--remember` cache stores ONLY the derived key (never the password),
 * only in the OS keychain, keyed by host+salt, always with a TTL. If keytar
 * is unavailable the cache is silently skipped with a warning — nothing is
 * ever plaintext-cached to `~/.2fav/`.
 */

import { CliError, apiGet, apiPost, apiPatch, resolveCredentials } from './api.js';
import { promptHiddenRequired } from './prompt.js';
import { deriveKey, importAesKey, decryptSecret, verifyTestValue, bytesToBase64, base64ToBytes } from './crypto.js';
import { computeTotp, computeHotp, computeSteam, getTimeRemaining } from './otp.js';
import * as keychain from './keychain.js';
import type { EncryptedAccount, EncryptedAccountListResponse } from '../types.js';

/** Default TTL for `--remember` (hours). */
export const DEFAULT_REMEMBER_HOURS = 8;

/** Shape of `GET /encryption/info`. */
interface EncryptionInfo {
    encryption_enabled?: boolean;
    encryption_salt?: string;
    encryption_test_value?: string;
    encryption_version?: number;
    vault_locked?: boolean;
}

/** Options for {@link ensureKey}. */
export interface EnsureKeyOptions {
    /** Opt-in derived-key cache TTL in hours (`--remember`). */
    rememberHours?: number;
}

/**
 * Test seams: the api + prompt dependencies, defaulting to the real modules.
 * Tests inject fakes here because the module registry is shared across test
 * files and `vault.js` may be cached with another file's api mock bound.
 */
export interface VaultDeps {
    apiGet?: (path: string, init?: RequestInit) => Promise<unknown>;
    apiPost?: (path: string, body: unknown, init?: RequestInit) => Promise<unknown>;
    apiPatch?: (path: string, body: unknown, init?: RequestInit) => Promise<unknown>;
    prompt?: (label: string, missingInputMessage: string) => Promise<string>;
}

/** An unlocked vault key plus the salt it was derived from. */
export interface UnlockedKey {
    keyBytes: Uint8Array;
    salt: string;
}

/**
 * Return an unlocked vault key, from the `--remember` cache when valid or via
 * a master-password prompt otherwise. Throws when the instance does not use
 * E2EE or the password fails verification twice.
 */
export async function ensureKey(options: EnsureKeyOptions = {}, deps: VaultDeps = {}): Promise<UnlockedKey> {
    const apiGetDep = deps.apiGet ?? apiGet;
    const apiPostDep = deps.apiPost ?? apiPost;
    const promptDep = deps.prompt ?? promptHiddenRequired;
    const creds = await resolveCredentials();
    const info = (await apiGetDep('/encryption/info')) as EncryptionInfo;

    if (!info.encryption_enabled || !info.encryption_salt || !info.encryption_test_value) {
        throw new CliError('This vault does not have E2EE enabled — nothing to unlock.');
    }
    const { encryption_salt: salt, encryption_test_value: testValue } = info;

    let keyBytes: Uint8Array | null = null;
    let freshUnlock = false;

    // 1. Cache hit path (cheap local safety net against a rotated password).
    // A hard keytar failure here degrades to a fresh unlock — never a crash.
    if (await keychain.isAvailable()) {
        let cached: keychain.DerivedKeyEntry | null = null;
        try {
            cached = await keychain.getDerivedKey(creds.host, salt);
        } catch {
            cached = null;
        }
        if (cached) {
            try {
                const bytes = base64ToBytes(cached.keyB64);
                if (await verifyTestValue(testValue, await importAesKey(bytes))) {
                    keyBytes = bytes;
                } else {
                    // Stale key (password rotated since caching): purge before prompting.
                    await keychain.removeDerivedKey(creds.host, salt).catch(() => {});
                }
            } catch {
                // Corrupted entry (bad base64, wrong key length): purge and
                // fall through to a fresh unlock — never a crash.
                await keychain.removeDerivedKey(creds.host, salt).catch(() => {});
            }
        }
    }

    // 2. Fresh unlock path: prompt → derive → verify, one retry.
    if (!keyBytes) {
        freshUnlock = true;
        keyBytes = await promptAndDerive(salt, testValue, promptDep);
    }

    // 3. Attest success at most once per cache lifetime. Budget note (RT-12):
    // /encryption/verify is rate-limited 5/min per IP shared by everyone
    // behind the same egress — treat 429 and any network error as
    // "skip attest, continue silently".
    if (freshUnlock) {
        try {
            await apiPostDep('/encryption/verify', { verification_result: true });
        } catch {
            /* attestation is best-effort */
        }
        // Opt-in `--remember`: cache the derived key (never the password).
        if (options.rememberHours !== undefined) {
            await rememberKey({ keyBytes, salt }, options.rememberHours);
        }
    }

    return { keyBytes, salt };
}

/**
 * Prompt for the master password (muted echo), derive and verify. On failure
 * purge any cached entry for the salt and re-prompt once, then give up with
 * the generic error (no oracle beyond what the web app exposes).
 */
async function promptAndDerive(
    salt: string,
    testValue: string,
    prompt: (label: string, missingInputMessage: string) => Promise<string>,
): Promise<Uint8Array> {
    const creds = await resolveCredentials();
    for (let attempt = 1; attempt <= 2; attempt++) {
        const password = await prompt(
            'Master password: ',
            'Master password required to unlock the vault (run interactively or pipe it via stdin).',
        );
        try {
            const keyBytes = await deriveKey(password, salt);
            if (await verifyTestValue(testValue, await importAesKey(keyBytes))) {
                return keyBytes;
            }
        } catch (err) {
            if (err instanceof CliError) throw err;
            // derive/verify failures behave like a wrong password (generic).
        }
        // Wrong password: purge the cache BEFORE erroring or re-prompting —
        // stale keys are more dangerous than absent ones.
        await keychain.removeDerivedKey(creds.host, salt).catch(() => {});
        if (attempt === 1) {
            console.error('Master password incorrect. Try again.');
        }
    }
    throw new CliError('Master password verification failed. The vault stays locked.');
}

/**
 * Cache the derived key for `--remember` (opt-in). Never the password. When
 * the OS keychain is unavailable the cache is skipped with a warning — no
 * plaintext fallback exists for key material by design.
 */
export async function rememberKey(unlocked: UnlockedKey, rememberHours?: number): Promise<void> {
    const hours = parseRememberHours(rememberHours);
    if (hours === undefined) return;
    if (!(await keychain.isAvailable())) {
        console.error('warning: --remember ignored — the OS keychain is unavailable in this environment.');
        return;
    }
    try {
        const creds = await resolveCredentials();
        await keychain.storeDerivedKey({
            host: creds.host,
            salt: unlocked.salt,
            keyB64: bytesToBase64(unlocked.keyBytes),
            derivedAt: Date.now(),
            ttlMs: hours * 3_600_000,
        });
    } catch {
        console.error('warning: --remember ignored — writing to the OS keychain failed.');
    }
}

/** Parse `--remember [hours]` — true/undefined → default 8h; numeric string validated. */
export function parseRememberHours(value?: string | boolean | number): number | undefined {
    if (value === undefined || value === false) return undefined;
    if (value === true) return DEFAULT_REMEMBER_HOURS;
    // Number() rejects trailing garbage ('5abc') that parseFloat would accept.
    const n = typeof value === 'number' ? value : Number(value);
    if (!Number.isFinite(n) || n <= 0) {
        throw new CliError(`Invalid --remember value '${value}' — pass a positive number of hours.`);
    }
    return n;
}

/**
 * Fetch the encrypted-accounts list once (`GET /twofaccounts/encrypted`) —
 * it carries id/params/ciphertext for ALL the caller's encrypted accounts.
 */
export async function fetchEncryptedAccounts(deps: VaultDeps = {}): Promise<EncryptedAccount[]> {
    const apiGetDep = deps.apiGet ?? apiGet;
    const body = (await apiGetDep('/twofaccounts/encrypted')) as EncryptedAccountListResponse | null;
    return body?.data ?? [];
}

/** Look up one account in the encrypted list — null when it is not E2EE. */
export async function findEncryptedAccount(id: number, deps: VaultDeps = {}): Promise<EncryptedAccount | null> {
    return (await fetchEncryptedAccounts(deps)).find((a) => a.id === id) ?? null;
}

/**
 * Compute an OTP locally for an E2EE account: decrypt the secret with the
 * unlocked key, then TOTP/HOTP/Steam from local time. HOTP advances the
 * server counter with a single adopt-on-422 recovery cycle (RT-12: the 422
 * body is message-only, so the fresh counter comes from a re-fetch).
 */
export async function localOtp(account: EncryptedAccount, keyBytes: Uint8Array, deps: VaultDeps = {}): Promise<string> {
    const apiPatchDep = deps.apiPatch ?? apiPatch;
    const apiGetDep = deps.apiGet ?? apiGet;
    const key = await importAesKey(keyBytes);

    let envelope: { ciphertext: string; iv: string; authTag: string };
    try {
        envelope = JSON.parse(account.secret);
    } catch {
        throw new CliError(
            `Account ${account.id} has an unreadable E2EE secret (not a ciphertext envelope). ` +
                'If it is team-shared, this CLI cannot unwrap it — use the web app or browser extension.',
        );
    }

    let secret: string;
    try {
        secret = await decryptSecret(envelope, key);
    } catch {
        throw new CliError(
            `Could not decrypt the secret of account ${account.id} with this vault key. ` +
                'If the account is team-shared, this CLI cannot unwrap it — use the web app or browser extension.',
        );
    }

    const digits = account.digits ?? 6;
    const algorithm = account.algorithm ?? 'sha1';

    if (account.period !== undefined && account.period !== null && account.period <= 0) {
        throw new CliError(`Account ${account.id} has an invalid TOTP period: ${account.period}.`);
    }

    switch (account.otp_type) {
        case 'hotp': {
            const counter = typeof account.counter === 'number' ? account.counter : 0;
            return hotpWithCounterSync(account.id, secret, counter, digits, algorithm, apiPatchDep, apiGetDep);
        }
        case 'steamtotp':
            return computeSteam(secret);
        case 'totp':
            return computeTotp(secret, { digits, period: account.period ?? 30, algorithm });
        default:
            // Fail closed: an unknown otp_type must not silently fall through
            // to TOTP and print a wrong code.
            throw new CliError(
                `Account ${account.id} has unsupported otp_type "${account.otp_type ?? 'unknown'}".`,
            );
    }
}

/**
 * HOTP with server counter sync: compute at the known counter, then PATCH
 * counter+1 (server requires strictly greater). A 422 (non-monotonic —
 * another device already advanced it) adopts the server counter once:
 * re-fetch, compute at the fresh counter, PATCH fresh+1. A second failure
 * errors out — never blind-increment.
 */
async function hotpWithCounterSync(
    id: number,
    secret: string,
    counter: number,
    digits: number,
    algorithm: string,
    apiPatchDep: (path: string, body: unknown, init?: RequestInit) => Promise<unknown>,
    apiGetDep: (path: string, init?: RequestInit) => Promise<unknown>,
): Promise<string> {
    const code = await computeHotp(secret, { counter, digits, algorithm });
    try {
        await apiPatchDep(`/twofaccounts/${id}/counter`, { counter: counter + 1 });
        return code;
    } catch (err) {
        if (!(err instanceof CliError && err.status === 422)) throw err;
    }

    // One recovery cycle: adopt the server's counter.
    const body = (await apiGetDep('/twofaccounts/encrypted')) as EncryptedAccountListResponse | null;
    const fresh = (body?.data ?? []).find((a) => a.id === id);
    const freshCounter = typeof fresh?.counter === 'number' ? fresh.counter : null;
    if (freshCounter === null) {
        throw new CliError(`HOTP counter sync failed: account ${id} disappeared from the encrypted list.`);
    }
    const freshCode = await computeHotp(secret, { counter: freshCounter, digits, algorithm });
    try {
        await apiPatchDep(`/twofaccounts/${id}/counter`, { counter: freshCounter + 1 });
    } catch {
        throw new CliError(
            `HOTP counter sync failed twice for account ${id} ` +
                `(server counter ${freshCounter}). Open the web app once to resynchronize.`,
        );
    }
    return freshCode;
}

/** Seconds until the current TOTP period rolls over (for local --watch). */
export function localPeriodRemaining(period: number): number {
    return getTimeRemaining(period);
}
