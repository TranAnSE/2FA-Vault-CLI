/**
 * Vault unlock + local OTP orchestration tests (CLI phase 2).
 *
 * Strategy: `vault.js` accepts injected api/prompt dependencies (VaultDeps) —
 * the module registry is shared across test files, so mocks are injected per
 * call instead of registered globally. The keychain is REAL, driven by a
 * mocked `keytar` (in-memory); Argon2id/AES run for real (deterministic,
 * ~1s per fresh unlock). No real network or OS keychain is touched.
 */

import { test, expect, mock, beforeEach } from 'bun:test';

// ---- deterministic AES seal helper (mirrors crypto.js encryptSecret) ----

async function sealWith(keyBytes: Uint8Array, plaintext: string): Promise<string> {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const combined = new Uint8Array(
        await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, new TextEncoder().encode(plaintext)),
    );
    const b64 = (b: Uint8Array) => btoa(String.fromCodePoint(...b));
    const tagLen = 16;
    return JSON.stringify({
        ciphertext: b64(combined.slice(0, -tagLen)),
        iv: b64(iv),
        authTag: b64(combined.slice(-tagLen)),
    });
}

function toHex(bytes: Uint8Array): string {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// ---- shared fixture state ----

const TEST_HOST = 'https://vault.example.com';
const TEST_PAT = 'pat-SECRET';
// 32-byte salt (bytes 0..31), base64.
const SALT_B64 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

const { deriveKey } = await import('../crypto.js');
const { CliError } = await import('../api.js');
type CliErrorInstance = InstanceType<typeof CliError>;

// Real Argon2id, derived once and shared by the whole file (~1s).
const VAULT_PASSWORD = 'master-pass-1';
const VAULT_KEY = await deriveKey(VAULT_PASSWORD, SALT_B64);
const TEST_VALUE = await sealWith(VAULT_KEY, 'VERIFICATION_TEST_VALUE');
const SECRET_PLAIN = 'JBSWY3DPEHPK3PXP';
const SECRET_ENVELOPE = await sealWith(VAULT_KEY, SECRET_PLAIN);
// A decoy key for wrong-password / stale-cache / team-shared scenarios.
const OTHER_KEY = await deriveKey('other-pass', SALT_B64);

interface FakeEncryptionInfo {
    encryption_enabled?: boolean;
    encryption_salt?: string;
    encryption_test_value?: string;
}

const state = {
    keytarStore: new Map<string, string>(),
    keytarBroken: false,
    info: {
        encryption_enabled: true,
        encryption_salt: SALT_B64,
        encryption_test_value: TEST_VALUE,
    } as FakeEncryptionInfo,
    encryptedList: [] as Record<string, unknown>[],
    counterPatches: [] as number[],
    counterFailuresRemaining: 0,
    attestCalls: 0,
};

const fakeKeytar = {
    setPassword: mock((_s: string, account: string, password: string) => {
        if (state.keytarBroken) return Promise.reject(new Error('keytar broken'));
        state.keytarStore.set(account, password);
        return Promise.resolve();
    }),
    getPassword: mock((_s: string, account: string) => {
        if (state.keytarBroken) return Promise.reject(new Error('keytar broken'));
        return Promise.resolve(state.keytarStore.get(account) ?? null);
    }),
    deletePassword: mock((_s: string, account: string) => {
        if (state.keytarBroken) return Promise.reject(new Error('keytar broken'));
        state.keytarStore.delete(account);
        return Promise.resolve(true);
    }),
    findCredentials: mock(() => {
        if (state.keytarBroken) return Promise.reject(new Error('keytar broken'));
        return Promise.resolve(
            [...state.keytarStore.entries()].map(([account, password]) => ({ account, password })),
        );
    }),
};
mock.module('keytar', () => fakeKeytar);

// Dynamic imports AFTER mocks are registered.
const keychain = await import('../keychain.js');
const vault = await import('../vault.js');
const otp = await import('../otp.js');

// ---- injected dependencies ----

let prompts: string[];

function scriptedPrompt(): Promise<string> {
    return Promise.resolve(prompts.shift() ?? '');
}

const injectedApiGet = async (path: string) => {
    if (path === '/encryption/info') return state.info;
    if (path.startsWith('/twofaccounts/encrypted')) return { data: state.encryptedList };
    throw new CliError(`unexpected apiGet: ${path}`);
};

const injectedApiPost = async (path: string) => {
    if (path === '/encryption/verify') {
        state.attestCalls++;
        return { message: 'ok', vault_locked: false };
    }
    throw new CliError(`unexpected apiPost: ${path}`);
};

const injectedApiPatch = async (path: string, body: unknown) => {
    if (path.includes('/counter')) {
        state.counterPatches.push((body as { counter: number }).counter);
        if (state.counterFailuresRemaining > 0) {
            state.counterFailuresRemaining--;
            throw new CliError('The counter must be greater than the current one.', 1, 422);
        }
        return { id: 1 };
    }
    throw new CliError(`unexpected apiPatch: ${path}`);
};

const deps = () => ({
    apiGet: injectedApiGet,
    apiPost: injectedApiPost,
    apiPatch: injectedApiPatch,
    prompt: scriptedPrompt,
});

beforeEach(() => {
    state.keytarStore.clear();
    state.keytarStore.set(TEST_HOST, JSON.stringify({ host: TEST_HOST, pat: TEST_PAT }));
    state.keytarBroken = false;
    state.info = { encryption_enabled: true, encryption_salt: SALT_B64, encryption_test_value: TEST_VALUE } as typeof state.info;
    state.encryptedList = [];
    state.counterPatches = [];
    state.counterFailuresRemaining = 0;
    state.attestCalls = 0;
    prompts = [];
});

const baseAccount = {
    id: 42,
    service: 'GitHub',
    account: 'alice',
    otp_type: 'totp',
    secret: SECRET_ENVELOPE,
    encrypted: true,
    digits: 6,
    algorithm: 'sha1',
    period: 30,
};

async function cacheTheVaultKey(ttlMs = 8 * 3_600_000): Promise<void> {
    await keychain.storeDerivedKey({
        host: TEST_HOST,
        salt: SALT_B64,
        keyB64: btoa(String.fromCodePoint(...VAULT_KEY)),
        derivedAt: Date.now(),
        ttlMs,
    });
}

// ---- ensureKey ----

test('ensureKey performs a fresh unlock: prompt → derive → verify → attest once', async () => {
    prompts = [VAULT_PASSWORD];
    const key = await vault.ensureKey({}, deps());
    expect(toHex(key.keyBytes)).toBe(toHex(VAULT_KEY));
    expect(key.salt).toBe(SALT_B64);
    expect(state.attestCalls).toBe(1);
}, 30_000);

test('ensureKey uses a valid cache entry: no prompt, no attest', async () => {
    await cacheTheVaultKey();
    const key = await vault.ensureKey({}, deps());
    expect(toHex(key.keyBytes)).toBe(toHex(VAULT_KEY));
    expect(prompts.length).toBe(0);
    expect(state.attestCalls).toBe(0);
}, 30_000);

test('ensureKey purges an expired cache entry and re-prompts', async () => {
    await cacheTheVaultKey(-1); // already expired
    prompts = [VAULT_PASSWORD];
    const key = await vault.ensureKey({}, deps());
    expect(toHex(key.keyBytes)).toBe(toHex(VAULT_KEY));
    // The expired entry was purged; remember was not requested so none was stored.
    expect(state.keytarStore.has(keychain.derivedKeyAccount(TEST_HOST, SALT_B64))).toBe(false);
    expect(state.attestCalls).toBe(1);
}, 30_000);

test('ensureKey ignores a cache entry for a different salt (multi-vault salts)', async () => {
    const otherSalt = 'u7d3hZ0kQ0mR0G0p0G0p0G0p0G0p0G0p0G0p0G0p0G0=';
    await keychain.storeDerivedKey({
        host: TEST_HOST,
        salt: otherSalt,
        keyB64: btoa(String.fromCodePoint(...OTHER_KEY)),
        derivedAt: Date.now(),
        ttlMs: 3_600_000,
    });
    prompts = [VAULT_PASSWORD];
    const key = await vault.ensureKey({}, deps());
    expect(toHex(key.keyBytes)).toBe(toHex(VAULT_KEY)); // fresh derive, not the other salt's key
    expect(state.attestCalls).toBe(1);
}, 30_000);

test('ensureKey purges a stale cached key that fails the cheap verify', async () => {
    await keychain.storeDerivedKey({
        host: TEST_HOST,
        salt: SALT_B64,
        keyB64: btoa(String.fromCodePoint(...OTHER_KEY)), // sealed under the OLD password
        derivedAt: Date.now(),
        ttlMs: 3_600_000,
    });
    prompts = [VAULT_PASSWORD];
    const key = await vault.ensureKey({}, deps());
    expect(toHex(key.keyBytes)).toBe(toHex(VAULT_KEY));
    // The stale entry was purged before the fresh derive.
    expect(state.keytarStore.has(keychain.derivedKeyAccount(TEST_HOST, SALT_B64))).toBe(false);
}, 30_000);

test('ensureKey re-prompts once on a wrong password, then succeeds', async () => {
    prompts = ['wrong-pass', VAULT_PASSWORD];
    const key = await vault.ensureKey({}, deps());
    expect(toHex(key.keyBytes)).toBe(toHex(VAULT_KEY));
    expect(state.attestCalls).toBe(1);
}, 30_000);

test('ensureKey errors after two wrong passwords without attesting', async () => {
    prompts = ['nope', 'also-nope'];
    let caught: unknown;
    await vault.ensureKey({}, deps()).catch((e) => (caught = e));
    expect(caught).toBeInstanceOf(CliError);
    expect((caught as CliErrorInstance).message).toContain('Master password verification failed');
    expect(state.attestCalls).toBe(0);
}, 30_000);

test('ensureKey errors when the vault has no E2EE', async () => {
    state.info = { encryption_enabled: false };
    let caught: unknown;
    await vault.ensureKey({}, deps()).catch((e) => (caught = e));
    expect((caught as CliErrorInstance).message).toContain('does not have E2EE');
});

test('ensureKey with --remember stores the key; second run is prompt-free', async () => {
    prompts = [VAULT_PASSWORD];
    await vault.ensureKey({ rememberHours: 1 }, deps());
    expect(state.keytarStore.has(keychain.derivedKeyAccount(TEST_HOST, SALT_B64))).toBe(true);

    const second = await vault.ensureKey({ rememberHours: 1 }, deps());
    expect(toHex(second.keyBytes)).toBe(toHex(VAULT_KEY));
    expect(prompts.length).toBe(0);
    expect(state.attestCalls).toBe(1); // from the first run only — cache hit attests nothing
}, 30_000);

test('rememberKey warns and continues when the keychain is broken (insecure-store semantics)', async () => {
    state.keytarBroken = true;
    // Must not throw; the cache is silently skipped with a warning.
    await vault.rememberKey({ keyBytes: VAULT_KEY, salt: SALT_B64 }, 1);
    expect(state.keytarStore.has(keychain.derivedKeyAccount(TEST_HOST, SALT_B64))).toBe(false);
});

// ---- parseRememberHours ----

test('parseRememberHours: flag default 8h, numeric strings, rejects junk', () => {
    expect(vault.parseRememberHours(undefined)).toBeUndefined();
    expect(vault.parseRememberHours(false)).toBeUndefined();
    expect(vault.parseRememberHours(true)).toBe(8);
    expect(vault.parseRememberHours('3')).toBe(3);
    expect(vault.parseRememberHours('0.5')).toBe(0.5);
    expect(() => vault.parseRememberHours('-1')).toThrow(/Invalid --remember/);
    expect(() => vault.parseRememberHours('abc')).toThrow(/Invalid --remember/);
});

// ---- localOtp ----

test('localOtp computes TOTP locally from the decrypted secret', async () => {
    state.encryptedList = [baseAccount];
    const code = await vault.localOtp(baseAccount as never, VAULT_KEY, deps());
    const expected = await otp.computeTotp(SECRET_PLAIN, { digits: 6, period: 30, algorithm: 'sha1' });
    expect(code).toBe(expected);
});

test('localOtp honors digits/period/algorithm from the account', async () => {
    const account = { ...baseAccount, digits: 8, period: 60, algorithm: 'sha256' };
    const code = await vault.localOtp(account as never, VAULT_KEY, deps());
    const expected = await otp.computeTotp(SECRET_PLAIN, { digits: 8, period: 60, algorithm: 'sha256' });
    expect(code).toBe(expected);
});

test('localOtp computes Steam OTP for steamtotp accounts', async () => {
    const account = { ...baseAccount, otp_type: 'steamtotp' };
    const code = await vault.localOtp(account as never, VAULT_KEY, deps());
    const expected = await otp.computeSteam(SECRET_PLAIN);
    expect(code).toBe(expected);
});

test('localOtp syncs the HOTP counter after generating', async () => {
    const account = { ...baseAccount, otp_type: 'hotp', counter: 5 };
    const code = await vault.localOtp(account as never, VAULT_KEY, deps());
    const expected = await otp.computeHotp(SECRET_PLAIN, { counter: 5 });
    expect(code).toBe(expected);
    expect(state.counterPatches).toEqual([6]);
});

test('localOtp adopts the server counter once on a 422 (non-monotonic)', async () => {
    const account = { ...baseAccount, otp_type: 'hotp', counter: 5 };
    state.counterFailuresRemaining = 1;
    // Another device advanced the counter to 9 meanwhile.
    state.encryptedList = [{ ...account, counter: 9 }];

    const code = await vault.localOtp(account as never, VAULT_KEY, deps());
    const expected = await otp.computeHotp(SECRET_PLAIN, { counter: 9 });
    expect(code).toBe(expected);
    expect(state.counterPatches).toEqual([6, 10]);
});

test('localOtp errors out after a second 422 (never blind-increments)', async () => {
    const account = { ...baseAccount, otp_type: 'hotp', counter: 5 };
    state.counterFailuresRemaining = 2;
    state.encryptedList = [{ ...account, counter: 9 }];

    let caught: unknown;
    await vault.localOtp(account as never, VAULT_KEY, deps()).catch((e) => (caught = e));
    expect((caught as CliErrorInstance).message).toContain('failed twice');
    expect(state.counterPatches).toEqual([6, 10]);
});

test('localOtp fails with the team-share pointer when the secret will not decrypt', async () => {
    const otherEnvelope = await sealWith(OTHER_KEY, SECRET_PLAIN);
    const account = { ...baseAccount, secret: otherEnvelope };
    let caught: unknown;
    await vault.localOtp(account as never, VAULT_KEY, deps()).catch((e) => (caught = e));
    expect((caught as CliErrorInstance).message).toContain('team-shared');
});

test('localOtp fails cleanly on a malformed secret envelope', async () => {
    const account = { ...baseAccount, secret: 'not-json' };
    let caught: unknown;
    await vault.localOtp(account as never, VAULT_KEY, deps()).catch((e) => (caught = e));
    expect((caught as CliErrorInstance).message).toContain('unreadable E2EE secret');
});

// ---- api special case (real api module + fetch mock) ----

test('a failed /encryption/verify 401 gets the vault-specific message, not the PAT hint', async () => {
    const { apiPost } = await import('../api.js');
    const fetchMock = mock(() =>
        Promise.resolve(
            new Response(JSON.stringify({ message: 'Verification failed', vault_locked: true }), {
                status: 401,
                headers: { 'content-type': 'application/json' },
            }),
        ),
    );
    const originalFetch = globalThis.fetch;
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    try {
        let caught: unknown;
        await apiPost('/encryption/verify', { verification_result: true }).catch((e) => (caught = e));
        expect(caught).toBeInstanceOf(CliError);
        expect((caught as CliErrorInstance).message).toContain('Master password verification failed');
        expect((caught as CliErrorInstance).message).not.toContain('PAT');
    } finally {
        globalThis.fetch = originalFetch;
    }
});
