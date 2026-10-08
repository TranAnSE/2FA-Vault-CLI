/**
 * Command-level E2EE tests (CLI phase 2): the `list` lock glyph and the
 * `get` server-OTP routing. The full unlock/decrypt/OTP flow is covered at
 * service level in vault.test.ts (with injected deps — the command modules
 * bind whatever api implementation was in Bun's shared registry first).
 *
 * Module notes:
 * - `list.js` is first imported by THIS file, so it binds the REAL api module
 *   and is driven through a mocked `globalThis.fetch`.
 * - `get.js` was already imported (and bound) by commands.test.ts, whose api
 *   mock owns the `/twofaccounts` fixtures — the server-path test asserts
 *   against those shared fixtures (GitHub → OTP 045698).
 */

import { test, expect, mock, beforeEach, afterEach, spyOn } from 'bun:test';

const state = {
    accounts: [
        { id: 1, service: 'GitHub', account: 'alice', otp_type: 'totp' },
        { id: 2, service: 'SecretSvc', account: 'bob', otp_type: 'totp' },
    ],
    encryptedIds: [2],
    infoCalls: 0,
    attestCalls: 0,
};

// ---- mocks ----

const fakeKeytar = {
    setPassword: mock(() => Promise.resolve()),
    getPassword: mock((_s: string, account: string) =>
        Promise.resolve(
            account === 'https://vault.example.com'
                ? JSON.stringify({ host: 'https://vault.example.com', pat: 'pat-SECRET' })
                : null,
        ),
    ),
    deletePassword: mock(() => Promise.resolve(true)),
    findCredentials: mock(() =>
        Promise.resolve([
            {
                account: 'https://vault.example.com',
                password: JSON.stringify({ host: 'https://vault.example.com', pat: 'pat-SECRET' }),
            },
        ]),
    ),
};
mock.module('keytar', () => fakeKeytar);

const fetchMock = mock((_input: string | URL | Request, _init?: RequestInit): Promise<Response> =>
    Promise.reject(new Error('fetch not configured for this test')),
);

function jsonResponse(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

beforeEach(() => {
    state.infoCalls = 0;
    state.attestCalls = 0;
    fetchMock.mockReset();
    fetchMock.mockImplementation((input: string | URL | Request) => {
        const url = String(input);
        if (url.endsWith('/encryption/info')) {
            state.infoCalls++;
            return Promise.resolve(
                jsonResponse({
                    encryption_enabled: true,
                    encryption_salt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
                    encryption_test_value: '{}',
                }),
            );
        }
        if (url.endsWith('/encryption/verify')) {
            state.attestCalls++;
            return Promise.resolve(jsonResponse({ message: 'ok' }));
        }
        if (url.endsWith('/twofaccounts/encrypted')) {
            return Promise.resolve(
                jsonResponse({
                    data: state.encryptedIds.map((id) => ({
                        id,
                        service: 'SecretSvc',
                        account: 'bob',
                        otp_type: 'totp',
                        secret: '{"ciphertext":"x","iv":"y","authTag":"z"}',
                        encrypted: true,
                    })),
                }),
            );
        }
        if (url.includes('/twofaccounts')) {
            return Promise.resolve(jsonResponse({ data: state.accounts }));
        }
        return Promise.reject(new Error(`unexpected fetch: ${url}`));
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;
});

// Dynamic imports AFTER mocks are registered.
const { listCommand } = await import('../list.js');
const { getCommand } = await import('../get.js');

let logSpy: ReturnType<typeof spyOn>;
let errSpy: ReturnType<typeof spyOn>;
let printed: string[];

beforeEach(() => {
    printed = [];
    logSpy = spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
        printed.push(args.map(String).join(' '));
    });
    errSpy = spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
    logSpy.mockRestore();
    errSpy.mockRestore();
});

test('list marks E2EE accounts with a lock glyph and plain accounts without', async () => {
    // list.js binds the registry's api mock (commands.test.ts fixtures):
    // id 2 (GitLab) is in the encrypted set, id 1 (GitHub) is not.
    await listCommand.parseAsync([], { from: 'user' });
    const githubRow = printed.find((l) => l.includes('GitHub')) ?? '';
    const gitlabRow = printed.find((l) => l.includes('GitLab')) ?? '';
    expect(githubRow).not.toContain('🔒');
    expect(gitlabRow).toContain('🔒');
});

test('get on a non-E2EE account takes the server-OTP path without unlocking', async () => {
    await getCommand.parseAsync(['GitHub'], { from: 'user' });

    expect(printed).toContain('045698');
    expect(state.attestCalls).toBe(0);
    expect(state.infoCalls).toBe(0);
});
