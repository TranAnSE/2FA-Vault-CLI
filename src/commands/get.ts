/**
 * `2fav get <service> [--watch] [--copy] [--remember[=<hours>]]`
 *
 * Finds a single account by service/account name, then prints its OTP.
 *
 * Non-E2EE accounts take the server-side path: `GET /api/v1/twofaccounts/{id}/otp`.
 * E2EE accounts take the local path: the vault is unlocked locally (master
 * password → Argon2id → test-value verification), the secret envelope is
 * decrypted locally and the OTP is computed locally (mirrors the web app) —
 * the server never sees key material (see services/vault.ts).
 *
 * - `--watch` refreshes the OTP at the start of each period (HOTP has no
 *   period, so --watch is disabled for HOTP with a note).
 * - `--copy` additionally writes the password to the system clipboard.
 * - `--remember[=<hours>]` caches the derived key (never the password) in the
 *   OS keychain so subsequent runs skip the prompt (default 8h).
 */

import { Command } from 'commander';
import { apiGet, CliError } from '../services/api.js';
import { copyToClipboard } from '../services/clipboard.js';
import {
    ensureKey,
    parseRememberHours,
    fetchEncryptedAccounts,
    localOtp,
    localPeriodRemaining,
} from '../services/vault.js';
import type { Account, AccountListResponse, OtpResponse, EncryptedAccount } from '../types.js';

interface GetOptions {
    watch?: boolean;
    copy?: boolean;
    remember?: string | boolean;
}

export const getCommand = new Command('get')
    .description('Print the current one-time password for an account')
    .argument('<service>', 'Service name (or account) to search for')
    .option('--watch', 'Refresh the OTP at the start of each TOTP period until interrupted')
    .option('--copy', 'Also copy the OTP to the system clipboard')
    .option('--remember [hours]', 'Cache the derived key in the OS keychain (never the password); TTL in hours, default 8')
    .action(async (service: string, opts: GetOptions) => {
        const account = await findUniqueAccount(service);
        const rememberHours = parseRememberHours(opts.remember);

        const encrypted = await findEncryptedAccount(account.id);
        if (encrypted) {
            await printLocalOtp(encrypted, { rememberHours, copy: opts.copy ?? false });
            if (opts.watch) {
                await watchLocal(encrypted, { copy: opts.copy ?? false });
            }
            return;
        }

        await printOtp(account, opts);
        if (!opts.watch) return;

        // --watch is TOTP-only: HOTP has no period to align to.
        const period = await periodOf(account);
        if (!period) {
            console.error('note: --watch disabled for HOTP/period-less accounts.');
            return;
        }
        await watchLoop(account, period, opts);
    });

// ---- Local (E2EE) path ----

/** Look up the account in the encrypted list, if it is E2EE. */
async function findEncryptedAccount(id: number): Promise<EncryptedAccount | null> {
    const encrypted = await fetchEncryptedAccounts();
    return encrypted.find((a) => a.id === id) ?? null;
}

/** Unlock (if needed), compute the OTP locally, print (+copy) it once. */
async function printLocalOtp(
    encrypted: EncryptedAccount,
    opts: { rememberHours?: number; copy: boolean },
): Promise<void> {
    const key = await ensureKey({ rememberHours: opts.rememberHours });
    const password = await localOtp(encrypted, key.keyBytes);
    if (opts.copy) {
        await copyOrWarn(password);
    }
    console.log(password);
}

/** Local --watch loop: recompute at each period boundary, no re-fetch. */
async function watchLocal(encrypted: EncryptedAccount, opts: { copy: boolean }): Promise<void> {
    const period = encrypted.period && encrypted.period > 0 ? encrypted.period : 30;
    if (encrypted.otp_type === 'hotp') {
        console.error('note: --watch disabled for HOTP/period-less accounts.');
        return;
    }
    for (;;) {
        const sleepMs = localPeriodRemaining(period) * 1000;
        await sleep(sleepMs);
        await printLocalOtp(encrypted, { ...opts, rememberHours: undefined });
    }
}

// ---- Server-OTP path (non-E2EE) ----

/** Fetch and print one OTP, copying to clipboard when requested. */
async function printOtp(account: Account, opts: GetOptions): Promise<void> {
    const otp = await fetchOtp(account.id);
    if (opts.copy) {
        await copyOrWarn(otp.password);
    }
    console.log(otp.password);
}

/** Re-fetch and print the OTP at each period boundary, indefinitely. */
async function watchLoop(account: Account, period: number, opts: GetOptions): Promise<void> {
    // align to the next period boundary before looping
    for (;;) {
        const sleepMs = period * 1000 - (Date.now() % (period * 1000));
        await sleep(sleepMs);
        await printOtp(account, opts);
    }
}

/** Resolve the TOTP period for an account, or null when there is none. */
async function periodOf(account: Account): Promise<number | null> {
    if (account.otp_type === 'hotp') return null;
    if (typeof account.period === 'number' && account.period > 0) return account.period;
    // Fall back to the period reported by a fresh OTP response.
    const otp = await fetchOtp(account.id);
    return typeof otp.period === 'number' && otp.period > 0 ? otp.period : null;
}

/** Fetch the current OTP for an account id. */
async function fetchOtp(id: number): Promise<OtpResponse> {
    const otp = await apiGet<OtpResponse>(`/twofaccounts/${id}/otp`);
    if (!otp?.password) {
        throw new Error('The server returned an OTP response without a password field.');
    }
    return otp;
}

async function copyOrWarn(password: string): Promise<void> {
    const ok = await copyToClipboard(password);
    if (!ok) console.error('warning: could not copy to clipboard (no clipboard tool available).');
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Find exactly one account whose `service` (or `account`) matches `query`
 * case-insensitively as a substring. Throws a `CliError` on no match or an
 * ambiguous match.
 */
export async function findUniqueAccount(query: string): Promise<Account> {
    const body = await apiGet<AccountListResponse>('/twofaccounts?withOtp=0');
    const accounts = body?.data ?? [];
    const needle = query.trim().toLowerCase();

    const matches = accounts.filter((a) => {
        const service = (a.service ?? '').toLowerCase();
        const account = (a.account ?? '').toLowerCase();
        return service.includes(needle) || account.includes(needle);
    });

    if (matches.length === 0) {
        throw new CliError(`No account matched '${query}'.`);
    }
    if (matches.length > 1) {
        const lines = matches.map((a) => `  [${a.id}] ${accountLabel(a)}`).join('\n');
        throw new CliError(
            `Multiple accounts matched '${query}':\n${lines}\nUse a more specific name.`,
        );
    }
    return matches[0];
}

/** Human-readable `service — account` label (null-safe). */
function accountLabel(a: Account): string {
    const service = a.service ?? '(no service)';
    const account = a.account ?? '';
    return account ? `${service} — ${account}` : service;
}
