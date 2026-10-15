/**
 * Entry-point argument handling.
 *
 * `cli.ts` runs `await run(toUserArgs(process.argv))` at module scope, so the
 * tests exercise toUserArgs directly (importing cli.ts would execute it).
 */
import { test, expect } from 'bun:test';
import { toUserArgs } from '../cli.js';
import { toAccountRows } from '../types.js';

const row = { id: 1, service: 'GitHub', otp_type: 'totp' };

test('toAccountRows accepts the bare-array wire shape the backend sends', () => {
    expect(toAccountRows([row])).toEqual([row]);
});

test('toAccountRows accepts a {data} wrapper defensively', () => {
    expect(toAccountRows({ data: [row] })).toEqual([row]);
});

test('toAccountRows tolerates null and malformed bodies', () => {
    expect(toAccountRows(null)).toEqual([]);
    expect(toAccountRows({})).toEqual([]);
});

test('strips the two Bun-prepended tokens from a compiled standalone argv (windows shape)', () => {
    // Observed from a bun --compile binary on Windows (Bun 1.4): the first
    // token is the literal string "bun", the second the virtual exe path.
    const argv = ['bun', 'B:/~BUN/root/2fav-win-x64.exe', 'login', 'https://vault.example.com'];
    expect(toUserArgs(argv)).toEqual(['login', 'https://vault.example.com']);
});

test('strips the two Bun-prepended tokens from a compiled standalone argv (linux shape)', () => {
    const argv = ['bun', '/~BUN/root/2fav', 'get', 'github', '--watch'];
    expect(toUserArgs(argv)).toEqual(['get', 'github', '--watch']);
});

test('strips the interpreter + script tokens from a dev-mode argv', () => {
    const argv = ['C:/bun/bun.exe', 'src/cli.ts', 'list', '--filter', 'git'];
    expect(toUserArgs(argv)).toEqual(['list', '--filter', 'git']);
});

test('returns no user args when none were given', () => {
    expect(toUserArgs(['bun', '/~BUN/root/2fav'])).toEqual([]);
});
