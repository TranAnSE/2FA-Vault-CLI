/**
 * Keychain abstraction for storing the 2FA-Vault PAT + host.
 *
 * Primary store: the OS keychain via `keytar`
 *   - macOS Keychain
 *   - Windows Credential Manager
 *   - libsecret / GNOME Keyring / KWallet on Linux
 *
 * Fallback store: a JSON file at `~/.2fav/config.json` (mode 0600) when keytar
 * is unavailable at runtime (e.g. headless Linux without a secret service, or
 * a `bun build --compile` binary where the native binding did not bundle).
 *
 * The account key used inside the keychain is the host URL, so a user can hold
 * credentials for multiple instances simultaneously.
 */

import { homedir } from 'node:os';
import { join } from 'node:path';
import { mkdir, readFile, writeFile, chmod, stat } from 'node:fs/promises';
import type { ApiConfig } from '../types.js';

/** Service name presented to the OS keychain. */
export const KEYCHAIN_SERVICE = '2FA-Vault-CLI';

const FALLBACK_DIR = join(homedir(), '.2fav');
const FALLBACK_FILE = join(FALLBACK_DIR, 'config.json');
const FALLBACK_MODE = 0o600;

/** Lazily-imported keytar handle (may fail to load). */
let keytarModule: typeof import('keytar') | null | undefined;

/**
 * Import keytar lazily so a missing/broken native binding never crashes the
 * whole CLI at import time — it just forces the fallback store.
 */
async function loadKeytar(): Promise<typeof import('keytar') | null> {
    if (keytarModule !== undefined) return keytarModule;
    try {
        // Dynamic import so `bun build --compile` and environments without the
        // native binding still boot.
        keytarModule = await import('keytar');
        return keytarModule;
    } catch {
        keytarModule = null;
        return null;
    }
}

/** Returns true when the OS keychain is usable in this environment. */
export async function isAvailable(): Promise<boolean> {
    const keytar = await loadKeytar();
    return keytar !== null;
}

/**
 * Store PAT + host in the OS keychain. Throws only on a hard keytar failure;
 * callers should catch and route to the plaintext fallback explicitly via
 * {@link storeFallback}.
 */
export async function store(host: string, pat: string): Promise<void> {
    const keytar = await loadKeytar();
    if (!keytar) {
        throw new Error('keychain unavailable');
    }
    await keytar.setPassword(KEYCHAIN_SERVICE, host, JSON.stringify({ host, pat }));
}

/**
 * Read credentials for the given host. When `host` is omitted, returns the
 * first stored credential set (single-instance convenience).
 */
export async function get(host?: string): Promise<ApiConfig | null> {
    const keytar = await loadKeytar();
    if (!keytar) return null;

    if (host) {
        const raw = await keytar.getPassword(KEYCHAIN_SERVICE, host);
        return raw ? parseConfig(raw) : null;
    }

    // No host specified: return the first matching credential.
    const creds = await keytar.findCredentials(KEYCHAIN_SERVICE);
    for (const c of creds) {
        const parsed = parseConfig(c.password);
        if (parsed) return parsed;
    }
    return null;
}

/** Remove the credential for a host (or all of them when host is omitted). */
export async function remove(host?: string): Promise<void> {
    const keytar = await loadKeytar();
    if (!keytar) return;

    if (host) {
        await keytar.deletePassword(KEYCHAIN_SERVICE, host);
        return;
    }
    const creds = await keytar.findCredentials(KEYCHAIN_SERVICE);
    for (const c of creds) {
        await keytar.deletePassword(KEYCHAIN_SERVICE, c.account);
    }
}

function parseConfig(raw: string): ApiConfig | null {
    try {
        const obj = JSON.parse(raw) as Partial<ApiConfig>;
        if (typeof obj.host === 'string' && typeof obj.pat === 'string') {
            return { host: obj.host, pat: obj.pat };
        }
    } catch {
        /* not JSON — ignore */
    }
    return null;
}

// ---- Derived-key cache (opt-in `--remember`, TTL, one entry per host+salt) ----

/**
 * A cached vault key. ONLY the derived key is ever persisted — never the
 * master password — and only into the OS keychain, always with a TTL.
 */
export interface DerivedKeyEntry {
    host: string;
    /** base64 salt the key was derived from (the cache is salt-keyed). */
    salt: string;
    /** base64 of the raw 32-byte derived key. */
    keyB64: string;
    /** epoch ms when the key was derived. */
    derivedAt: number;
    /** time-to-live in ms. */
    ttlMs: number;
}

/** Suffix marking a keychain account as a derived-key cache entry. */
const DERIVED_KEY_SUFFIX = ':derived-key';

/**
 * Cache account key: `host + ':' + hex(sha256(salt)).slice(0,16) + ':derived-key'`.
 * Keyed by host AND salt so multi-salt vaults coexist (RT-12).
 */
export function derivedKeyAccount(host: string, salt: string): string {
    const digest = new Bun.CryptoHasher('sha256').update(salt).digest('hex');
    return `${host}:${digest.slice(0, 16)}${DERIVED_KEY_SUFFIX}`;
}

/** Store a derived-key cache entry. Throws on hard keytar failures. */
export async function storeDerivedKey(entry: DerivedKeyEntry): Promise<void> {
    const keytar = await loadKeytar();
    if (!keytar) throw new Error('keychain unavailable');
    await keytar.setPassword(
        KEYCHAIN_SERVICE,
        derivedKeyAccount(entry.host, entry.salt),
        JSON.stringify(entry),
    );
}

/**
 * Read the derived-key entry for a host+salt. Returns null when absent or
 * expired — expired entries are purged on read.
 */
export async function getDerivedKey(host: string, salt: string): Promise<DerivedKeyEntry | null> {
    const keytar = await loadKeytar();
    if (!keytar) return null;
    const raw = await keytar.getPassword(KEYCHAIN_SERVICE, derivedKeyAccount(host, salt));
    if (!raw) return null;
    let entry: DerivedKeyEntry | null = null;
    try {
        const obj = JSON.parse(raw) as Partial<DerivedKeyEntry>;
        if (
            typeof obj.host === 'string' &&
            typeof obj.salt === 'string' &&
            typeof obj.keyB64 === 'string' &&
            typeof obj.derivedAt === 'number' &&
            typeof obj.ttlMs === 'number'
        ) {
            entry = obj as DerivedKeyEntry;
        }
    } catch {
        /* not JSON — treat as absent */
    }
    if (entry && Date.now() > entry.derivedAt + entry.ttlMs) {
        await keytar.deletePassword(KEYCHAIN_SERVICE, derivedKeyAccount(host, salt));
        return null;
    }
    return entry;
}

/** Remove the derived-key entry for a host+salt (idempotent). */
export async function removeDerivedKey(host: string, salt: string): Promise<void> {
    const keytar = await loadKeytar();
    if (!keytar) return;
    await keytar.deletePassword(KEYCHAIN_SERVICE, derivedKeyAccount(host, salt));
}

/** Remove every derived-key entry across all hosts (`2fav logout`). */
export async function removeAllDerivedKeys(): Promise<void> {
    const keytar = await loadKeytar();
    if (!keytar) return;
    const creds = await keytar.findCredentials(KEYCHAIN_SERVICE);
    for (const c of creds) {
        if (c.account.endsWith(DERIVED_KEY_SUFFIX)) {
            await keytar.deletePassword(KEYCHAIN_SERVICE, c.account);
        }
    }
}

// ---- Plaintext fallback store (~/.2fav/config.json, mode 0600) ----

export async function fallbackExists(): Promise<boolean> {
    try {
        await stat(FALLBACK_FILE);
        return true;
    } catch {
        return false;
    }
}

export async function storeFallback(host: string, pat: string): Promise<void> {
    await mkdir(FALLBACK_DIR, { recursive: true });
    const payload: ApiConfig = { host, pat };
    await writeFile(FALLBACK_FILE, JSON.stringify(payload, null, 2), { mode: FALLBACK_MODE });
    // Re-assert 0600 in case the file already existed with looser bits.
    await chmod(FALLBACK_FILE, FALLBACK_MODE);
}

export async function getFallback(): Promise<ApiConfig | null> {
    try {
        const raw = await readFile(FALLBACK_FILE, 'utf8');
        const obj = JSON.parse(raw) as Partial<ApiConfig>;
        if (typeof obj.host === 'string' && typeof obj.pat === 'string') {
            return { host: obj.host, pat: obj.pat };
        }
        return null;
    } catch {
        return null;
    }
}

export async function removeFallback(): Promise<void> {
    const { rm } = await import('node:fs/promises');
    await rm(FALLBACK_FILE, { force: true });
}

export { FALLBACK_FILE as fallbackPath };
