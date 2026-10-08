/**
 * `2fav list [--filter <text>]`
 *
 * Calls `GET /api/v1/twofaccounts` and prints `service — account` per row.
 * E2EE accounts get a 🔒 glyph (they need a vault unlock before `get`/`copy`
 * can compute their OTP locally). The optional `--filter` performs a
 * client-side case-insensitive substring match against `service` or `account`.
 */

import { Command } from 'commander';
import { apiGet, CliError } from '../services/api.js';
import { fetchEncryptedAccounts } from '../services/vault.js';
import type { Account, AccountListResponse } from '../types.js';

export const listCommand = new Command('list')
    .description('List your 2FA accounts (service — account)')
    .option('--filter <text>', 'Case-insensitive substring filter on service or account')
    .option('--search <text>', 'Alias for --filter')
    .action(async (opts: { filter?: string; search?: string }) => {
        const body = await apiGet<AccountListResponse>('/twofaccounts?withOtp=0');
        const accounts = body?.data ?? [];
        const encryptedIds = new Set((await fetchEncryptedAccounts()).map((a) => a.id));

        const query = opts.filter ?? opts.search;
        const visible = query ? applyFilter(accounts, query) : accounts;
        if (visible.length === 0) {
            const suffix = query ? ` matching '${query}'` : '';
            throw new CliError(`No accounts found${suffix}.`);
        }

        for (const a of visible) {
            const glyph = encryptedIds.has(a.id) ? '🔒 ' : '';
            console.log(`[${a.id}] ${glyph}${label(a)}`);
        }
        console.log(`\n${visible.length} account${visible.length === 1 ? '' : 's'}.`);
    });

/** Client-side filter on service or account (null-safe). */
function applyFilter(accounts: Account[], filter: string): Account[] {
    const q = filter.trim().toLowerCase();
    if (!q) return accounts;
    return accounts.filter((a) => {
        const service = (a.service ?? '').toLowerCase();
        const account = (a.account ?? '').toLowerCase();
        return service.includes(q) || account.includes(q);
    });
}

/** Human-readable `service — account` label (null-safe). */
function label(a: Account): string {
    const service = a.service ?? '(no service)';
    const account = a.account ?? '';
    return account ? `${service} — ${account}` : service;
}
