/**
 * Unit tests for the fetch wrapper.
 *
 * Strategy: drive the REAL keychain module against a mocked `keytar` (no OS
 * keychain) so that `apiRequest` resolves deterministic credentials. We do NOT
 * mock `../services/keychain.js` itself (that would collide with keychain.test.ts
 * in Bun's shared module registry). `globalThis.fetch` is replaced with a
 * Bun `mock`. No real network or keychain is touched.
 */

import { test, expect, mock, beforeEach, afterEach } from 'bun:test';

// ---- mocked keytar: deterministic credentials for the host under test ----

const TEST_HOST = 'https://vault.example.com';
const TEST_PAT = 'pat-SECRET';

const fakeKeytar = {
    setPassword: mock(() => Promise.resolve()),
    getPassword: mock((_service: string, account: string) => {
        if (account === TEST_HOST) {
            return Promise.resolve(JSON.stringify({ host: TEST_HOST, pat: TEST_PAT }));
        }
        return Promise.resolve(null);
    }),
    deletePassword: mock(() => Promise.resolve(true)),
    findCredentials: mock((): Promise<Array<{ account: string; password: string }>> =>
        Promise.resolve([]),
    ),
};

mock.module('keytar', () => fakeKeytar);

// Plaintext fallback store returns nothing — api should read from the keychain.
const fakeFs = {
    mkdir: mock(() => Promise.resolve()),
    writeFile: mock(() => Promise.resolve()),
    readFile: mock(() => {
        const err: NodeJS.ErrnoException = new Error('ENOENT');
        err.code = 'ENOENT';
        return Promise.reject(err);
    }),
    chmod: mock(() => Promise.resolve()),
    stat: mock(() => {
        const err: NodeJS.ErrnoException = new Error('ENOENT');
        err.code = 'ENOENT';
        return Promise.reject(err);
    }),
    rm: mock(() => Promise.resolve()),
};
mock.module('node:fs/promises', () => fakeFs);

// Dynamic import so the module graph picks up the mocks.
const { CliError, apiGet, apiRequest } = await import('../services/api.js');
// A dynamic import yields a const binding — usable as a value, not a type.
type CliErrorInstance = InstanceType<typeof CliError>;

// ---- fetch mock ----

const fetchMock = mock(
    (_input: string | URL | Request, _init?: RequestInit): Promise<Response> =>
        Promise.reject(new Error('fetch not configured for this test')),
);

beforeEach(() => {
    fetchMock.mockClear();
    // mockReset() clears both call history AND per-test implementations, then
    // we re-establish the default happy-path credential resolution.
    fakeKeytar.getPassword.mockReset();
    fakeKeytar.findCredentials.mockReset();
    fakeKeytar.getPassword.mockImplementation((_service: string, account: string) => {
        if (account === TEST_HOST) {
            return Promise.resolve(JSON.stringify({ host: TEST_HOST, pat: TEST_PAT }));
        }
        return Promise.resolve(null);
    });
    fakeKeytar.findCredentials.mockImplementation(() =>
        Promise.resolve([
            { account: TEST_HOST, password: JSON.stringify({ host: TEST_HOST, pat: TEST_PAT }) },
        ]),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;
});

afterEach(() => {
    fetchMock.mockReset();
});

function jsonResponse(body: unknown, status = 200, statusText = 'OK'): Response {
    return new Response(JSON.stringify(body), {
        status,
        statusText,
        headers: { 'content-type': 'application/json' },
    });
}

// ---- tests ----

test('apiGet() returns parsed JSON on a 200', async () => {
    const payload = { data: [{ id: 1, service: 'GitHub', account: 'me', otp_type: 'totp' }] };
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse(payload)));

    const result = await apiGet<typeof payload>('/twofaccounts');

    expect(result).toEqual(payload);
    expect(fetchMock).toHaveBeenCalledTimes(1);
});

test('apiRequest() targets {host}/api/v1{path}', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse({ ok: true })));

    await apiRequest('/twofaccounts/1/otp');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toBe('https://vault.example.com/api/v1/twofaccounts/1/otp');
});

test('apiRequest() sends Authorization: Bearer <PAT> header', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse({ ok: true })));

    await apiRequest('/twofaccounts');

    const init = fetchMock.mock.calls[0][1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe('Bearer pat-SECRET');
    expect(headers.Accept).toBe('application/json');
});

test('apiRequest() strips a trailing slash from the host', async () => {
    // Override the keytar getPassword to return a host with trailing slashes.
    fakeKeytar.getPassword.mockImplementation((_s: string, _a: string) =>
        Promise.resolve(JSON.stringify({ host: 'https://vault.example.com///', pat: TEST_PAT })),
    );
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse({ ok: true })));

    await apiRequest('/twofaccounts');

    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toBe('https://vault.example.com/api/v1/twofaccounts');
});

test('apiRequest() rejects with CliError on a 401', async () => {
    fetchMock.mockImplementation(() =>
        Promise.resolve(jsonResponse({ message: 'Unauthenticated.' }, 401, 'Unauthorized')),
    );

    let caught: unknown;
    await apiRequest('/twofaccounts').catch((e) => (caught = e));
    expect(caught).toBeInstanceOf(CliError);
    expect((caught as CliErrorInstance).message).toContain('401');
});

test('apiRequest() rejects with CliError on a 404', async () => {
    fetchMock.mockImplementation(() =>
        Promise.resolve(jsonResponse({ message: 'Not found' }, 404, 'Not Found')),
    );

    let caught: unknown;
    await apiRequest('/twofaccounts/999').catch((e) => (caught = e));
    expect(caught).toBeInstanceOf(CliError);
    expect((caught as CliErrorInstance).message).toContain('404');
});

test('apiRequest() rejects with CliError on a network failure', async () => {
    fetchMock.mockImplementation(() => Promise.reject(new Error('ECONNREFUSED')));

    let caught: unknown;
    await apiRequest('/twofaccounts').catch((e) => (caught = e));
    expect(caught).toBeInstanceOf(CliError);
    expect((caught as CliErrorInstance).message).toContain('Could not reach');
});

test('apiRequest() rejects with a "Not logged in" CliError when no creds are stored', async () => {
    // Both keychain (keytar returns null) and fallback (file missing) are empty.
    fakeKeytar.getPassword.mockImplementation(() => Promise.resolve(null));
    fakeKeytar.findCredentials.mockImplementation(() => Promise.resolve([]));

    let caught: unknown;
    await apiRequest('/twofaccounts').catch((e) => (caught = e));
    expect(caught).toBeInstanceOf(CliError);
    expect((caught as CliErrorInstance).message.toLowerCase()).toContain('not logged in');
    // fetch must never have been called.
    expect(fetchMock).not.toHaveBeenCalled();
});

test('apiRequest() rejects on a non-JSON 2xx body', async () => {
    fetchMock.mockImplementation(() =>
        Promise.resolve(
            new Response('definitely not json', {
                status: 200,
                headers: { 'content-type': 'text/plain' },
            }),
        ),
    );

    let caught: unknown;
    await apiRequest('/twofaccounts').catch((e) => (caught = e));
    expect(caught).toBeInstanceOf(CliError);
    expect((caught as CliErrorInstance).message).toContain('non-JSON');
});

test('apiRequest() returns undefined for an empty 2xx body', async () => {
    fetchMock.mockImplementation(() =>
        Promise.resolve(new Response('', { status: 204, statusText: 'No Content' })),
    );

    const result = await apiRequest('/twofaccounts/1');
    expect(result).toBeUndefined();
});

test('CliError carries a non-zero exit code', () => {
    const err = new CliError('boom', 2);
    expect(err.exitCode).toBe(2);
    expect(err.message).toBe('boom');
    expect(err.name).toBe('CliError');
    // default exit code
    expect(new CliError('default').exitCode).toBe(1);
});
