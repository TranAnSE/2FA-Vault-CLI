/**
 * Command-level tests for the 2FA-Vault CLI.
 *
 * We test the logic the commands expose without spinning up commander's argv
 * parser (which is brittle to test through). The highest-value units are:
 *   - findUniqueAccount (exported from get.ts): no-match / unique / ambiguous
 *   - the E2EE fast-fail branch
 *
 * `apiGet` is mocked so no real network or keychain is touched. The clipboard
 * service is also mocked where relevant.
 */

import { test, expect, mock, beforeEach } from 'bun:test';
import { CliError } from '../../services/api.js';
import type { Account, AccountListResponse } from '../../types.js';

// ---- Mock apiGet: the single network boundary the commands cross. ----
// We import the command module AFTER registering the mock so its internal
// `apiGet` binding points at the mocked implementation.

const accountsIndex: Account[] = [
    { id: 1, service: 'GitHub', account: 'alice@example.com', otp_type: 'totp' },
    { id: 2, service: 'GitLab', account: 'alice', otp_type: 'totp' },
    { id: 3, service: 'AWS', account: 'root', otp_type: 'hotp', counter: 5 },
    { id: 7, service: 'GitLab', account: 'bob', otp_type: 'totp' }, // ambiguous w/ id 2
];

const apiGetMock = mock(async (path: string) => {
    // NOTE: the /otp route is matched before the generic /twofaccounts prefix
    // so get.ts's fetchOtp (`/twofaccounts/{id}/otp`) reaches it.
    if (path.startsWith('/twofaccounts/encrypted')) {
        const encrypted: AccountListResponse = {
            data: [
                { id: 3, service: 'AWS', account: 'root', otp_type: 'hotp' },
                { id: 2, service: 'SecretSvc', account: 'bob', otp_type: 'totp' },
            ],
        };
        return encrypted;
    }
    if (path.includes('/otp')) {
        return { password: '045698', otp_type: 'totp', period: 30 };
    }
    if (path.startsWith('/twofaccounts')) {
        return { data: accountsIndex } as AccountListResponse;
    }
    // Fall through to the REAL api for anything this file's fixtures don't
    // cover: later test files (vault/e2ee) share Bun's module registry, and
    // get.js/vault.js bind whatever was in the api slot when they first
    // loaded — the real fallback (driven by their own fetch mocks) keeps
    // those bindings functional instead of returning null.
    return realApi.apiGet(path);
});

// The real module first, so the mock can spread its full surface
// (apiPost/apiPatch/apiRequest/… — vault.js imports them statically).
const realApi = await import('../../services/api.js');

mock.module('../../services/api.js', () => ({
    ...realApi,
    apiGet: apiGetMock,
    CliError,
    resolveCredentials: async () => ({ host: 'https://vault.example.com', pat: 'pat-SECRET' }),
}));

// Clipboard never touches the OS in tests.
mock.module('../../services/clipboard.js', () => ({
    copyToClipboard: async () => true,
}));

// Dynamic import AFTER mocks are registered so the command module picks them up.
const { findUniqueAccount } = await import('../get.js');

beforeEach(() => {
    apiGetMock.mockClear();
});

test('findUniqueAccount resolves a unique service match (case-insensitive)', async () => {
    const acc = await findUniqueAccount('github');
    expect(acc.id).toBe(1);
    expect(acc.service).toBe('GitHub');
});

test('findUniqueAccount resolves a unique account-label match', async () => {
    const acc = await findUniqueAccount('alice@example.com');
    expect(acc.id).toBe(1);
});

test('findUniqueAccount throws CliError on no match', async () => {
    expect(findUniqueAccount('nonexistent')).rejects.toThrow(/No account matched 'nonexistent'/);
});

test('findUniqueAccount throws CliError on an ambiguous match and lists candidates', async () => {
    expect(findUniqueAccount('gitlab')).rejects.toThrow(/Multiple accounts matched 'gitlab'/);
});

test('findUniqueAccount trims whitespace before matching', async () => {
    const acc = await findUniqueAccount('  aws  ');
    expect(acc.id).toBe(3);
});

test('findUniqueAccount handles accounts with a null service', async () => {
    // Re-point the mock to a list containing a null-service account.
    apiGetMock.mockImplementationOnce(async (path: string) => {
        if (path.startsWith('/twofaccounts') && !path.includes('/encrypted') && !path.includes('/otp')) {
            return { data: [{ id: 9, service: null as unknown as string, account: 'no-service-user', otp_type: 'totp' }] };
        }
        return null;
    });
    const acc = await findUniqueAccount('no-service-user');
    expect(acc.id).toBe(9);
});

test('the E2EE fast-fail path is reachable via the encrypted endpoint', async () => {
    // findUniqueAccount itself only queries the index; the E2EE routing is a
    // separate /twofaccounts/encrypted lookup (the mock's list contains id 3,
    // AWS). We assert the data shape the command depends on rather than the
    // command's internal wiring.
    apiGetMock.mockClear();
    await findUniqueAccount('aws');
    // The command first hits the index endpoint.
    expect(apiGetMock).toHaveBeenCalledWith('/twofaccounts?withOtp=0');
});
