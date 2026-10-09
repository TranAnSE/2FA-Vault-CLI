/**
 * Unit tests for the OS keychain abstraction.
 *
 * The `keytar` native module and `node:fs/promises` are both mocked with
 * `mock.module` so no real OS keychain or filesystem is touched. Mocks are
 * registered BEFORE the keychain module is imported (via dynamic import) so the
 * module graph picks up the fakes.
 */

import { test, expect, mock, beforeEach } from 'bun:test';

// ---- in-memory fakes that stand in for the OS keychain + filesystem ----

const keytarStore = new Map<string, string>();

const fakeKeytar = {
    setPassword: mock((service: string, account: string, password: string) => {
        keytarStore.set(`${service}::${account}`, password);
        return Promise.resolve();
    }),
    getPassword: mock((service: string, account: string) =>
        Promise.resolve(keytarStore.get(`${service}::${account}`) ?? null),
    ),
    deletePassword: mock((service: string, account: string) => {
        keytarStore.delete(`${service}::${account}`);
        return Promise.resolve(true);
    }),
    findCredentials: mock((service: string) => {
        const out: Array<{ account: string; password: string }> = [];
        for (const [key, password] of keytarStore) {
            const [svc, account] = key.split('::');
            if (svc === service) out.push({ account, password });
        }
        return Promise.resolve(out);
    }),
};

// Mock `keytar` BEFORE importing keychain.ts (which loads it lazily).
mock.module('keytar', () => fakeKeytar);

// Filesystem fake for the plaintext fallback path.
const fsFiles = new Map<string, string>();
const fakeFs = {
    mkdir: mock(() => Promise.resolve(undefined)),
    writeFile: mock((path: string, data: string) => {
        fsFiles.set(path, data);
        return Promise.resolve(undefined);
    }),
    readFile: mock((path: string) => {
        const data = fsFiles.get(path);
        if (data === undefined) {
            const err: NodeJS.ErrnoException = new Error('ENOENT');
            err.code = 'ENOENT';
            return Promise.reject(err);
        }
        return Promise.resolve(data);
    }),
    chmod: mock((_path: string, _mode: number) => Promise.resolve(undefined)),
    stat: mock((path: string) => {
        if (!fsFiles.has(path)) {
            const err: NodeJS.ErrnoException = new Error('ENOENT');
            err.code = 'ENOENT';
            return Promise.reject(err);
        }
        return Promise.resolve(
            {} as unknown as Awaited<ReturnType<typeof import('node:fs/promises').stat>>,
        );
    }),
    rm: mock((path: string) => {
        fsFiles.delete(path);
        return Promise.resolve(undefined);
    }),
};

mock.module('node:fs/promises', () => fakeFs);

// Dynamic import AFTER mocks are registered.
const keychain = await import('../services/keychain.js');

beforeEach(() => {
    keytarStore.clear();
    fsFiles.clear();
    for (const m of [
        fakeKeytar.setPassword,
        fakeKeytar.getPassword,
        fakeKeytar.deletePassword,
        fakeKeytar.findCredentials,
        fakeFs.mkdir,
        fakeFs.writeFile,
        fakeFs.readFile,
        fakeFs.chmod,
        fakeFs.stat,
        fakeFs.rm,
    ]) {
        m.mockClear();
    }
});

// ---- tests ----

test('store() writes {host, pat} JSON via keytar.setPassword with service + host account', async () => {
    await keychain.store('https://vault.example.com', 'pat-SECRET');

    expect(fakeKeytar.setPassword).toHaveBeenCalledTimes(1);
    const [service, account, password] = fakeKeytar.setPassword.mock.calls[0];
    expect(service).toBe(keychain.KEYCHAIN_SERVICE);
    expect(account).toBe('https://vault.example.com');
    expect(JSON.parse(password)).toEqual({
        host: 'https://vault.example.com',
        pat: 'pat-SECRET',
    });
});

test('get() returns null when keytar has nothing for the host', async () => {
    const result = await keychain.get('https://nothing.example.com');
    expect(result).toBeNull();
});

test('get() returns parsed config when keytar has the credential', async () => {
    await keychain.store('https://vault.example.com', 'pat-SECRET');
    const result = await keychain.get('https://vault.example.com');
    expect(result).toEqual({ host: 'https://vault.example.com', pat: 'pat-SECRET' });
});

test('get() without host returns the first credential from findCredentials', async () => {
    await keychain.store('https://one.example.com', 'pat-ONE');
    await keychain.store('https://two.example.com', 'pat-TWO');
    const result = await keychain.get();
    expect(result).not.toBeNull();
    expect(result!.pat === 'pat-ONE' || result!.pat === 'pat-TWO').toBe(true);
});

test('remove(host) calls keytar.deletePassword for that host', async () => {
    await keychain.store('https://vault.example.com', 'pat-SECRET');
    fakeKeytar.deletePassword.mockClear();

    await keychain.remove('https://vault.example.com');

    expect(fakeKeytar.deletePassword).toHaveBeenCalledTimes(1);
    const [service, account] = fakeKeytar.deletePassword.mock.calls[0];
    expect(service).toBe(keychain.KEYCHAIN_SERVICE);
    expect(account).toBe('https://vault.example.com');
    expect(await keychain.get('https://vault.example.com')).toBeNull();
});

test('remove() without host deletes every stored credential', async () => {
    await keychain.store('https://one.example.com', 'pat-ONE');
    await keychain.store('https://two.example.com', 'pat-TWO');

    await keychain.remove();

    expect(await keychain.get('https://one.example.com')).toBeNull();
    expect(await keychain.get('https://two.example.com')).toBeNull();
});

test('isAvailable() is true when keytar loads', async () => {
    expect(await keychain.isAvailable()).toBe(true);
});

// ---- plaintext fallback path ----

test('storeFallback() writes config JSON and chmods to 0600', async () => {
    await keychain.storeFallback('https://vault.example.com', 'pat-SECRET');

    expect(fakeFs.mkdir).toHaveBeenCalledTimes(1);
    expect(fakeFs.writeFile).toHaveBeenCalledTimes(1);
    const [path, data] = fakeFs.writeFile.mock.calls[0];
    expect(path).toBe(keychain.fallbackPath);
    expect(JSON.parse(data)).toEqual({
        host: 'https://vault.example.com',
        pat: 'pat-SECRET',
    });
    expect(fakeFs.chmod).toHaveBeenCalledTimes(1);
    expect(fakeFs.chmod.mock.calls[0][1]).toBe(0o600);
});

test('getFallback() returns null when the file does not exist', async () => {
    expect(await keychain.getFallback()).toBeNull();
});

test('getFallback() returns parsed config when the file exists', async () => {
    await keychain.storeFallback('https://vault.example.com', 'pat-SECRET');
    const result = await keychain.getFallback();
    expect(result).toEqual({ host: 'https://vault.example.com', pat: 'pat-SECRET' });
});

test('fallbackExists() reflects file presence', async () => {
    expect(await keychain.fallbackExists()).toBe(false);
    await keychain.storeFallback('https://vault.example.com', 'pat-SECRET');
    expect(await keychain.fallbackExists()).toBe(true);
});

test('removeFallback() deletes the file', async () => {
    await keychain.storeFallback('https://vault.example.com', 'pat-SECRET');
    expect(await keychain.fallbackExists()).toBe(true);
    await keychain.removeFallback();
    expect(await keychain.fallbackExists()).toBe(false);
});
