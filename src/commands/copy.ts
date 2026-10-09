/**
 * `2fav copy <service> [--remember[=<hours>]]`
 *
 * Same lookup + OTP as `get`, but writes the password to the system clipboard
 * instead of stdout. Prints a short confirmation on success. E2EE accounts
 * take the same local decrypt path as `get` (this command previously skipped
 * the E2EE check and surfaced the server's raw error — the asymmetry is gone).
 */

import { Command } from 'commander';
import { findUniqueAccount } from './get.js';
import { apiGet, CliError } from '../services/api.js';
import { copyToClipboard, clipboardBackendLabel } from '../services/clipboard.js';
import {
    ensureKey,
    parseRememberHours,
    findEncryptedAccount,
    localOtp,
} from '../services/vault.js';

interface CopyOptions {
    remember?: string | boolean;
}

export const copyCommand = new Command('copy')
    .description('Copy the current one-time password for an account to the clipboard')
    .argument('<service>', 'Service name (or account) to search for')
    .option('--remember [hours]', 'Cache the derived key in the OS keychain (never the password); TTL in hours, default 8')
    .action(async (service: string, opts: CopyOptions) => {
        const account = await findUniqueAccount(service);
        const rememberHours = parseRememberHours(opts.remember);

        const encrypted = await findEncryptedAccount(account.id);
        let password: string;
        if (encrypted) {
            const key = await ensureKey({ rememberHours });
            password = await localOtp(encrypted, key.keyBytes);
            // One-shot use: scrub the derived key. (The password string is
            // immutable JS — an accepted residual, same as the web app.)
            key.keyBytes.fill(0);
        } else {
            password = await fetchOtp(account.id);
        }

        const ok = await copyToClipboard(password);
        if (!ok) {
            throw new CliError(
                `Could not copy to clipboard. No clipboard tool was available ` +
                    `(looked for ${clipboardBackendLabel()}).`,
            );
        }
        console.log(
            `OTP copied to clipboard for ${account.service ?? account.account ?? 'account'}.`,
        );
    });

/** Fetch the server-side OTP password for a non-E2EE account. */
async function fetchOtp(id: number): Promise<string> {
    const otp = await apiGet<{ password: string }>(`/twofaccounts/${id}/otp`);
    if (!otp?.password) {
        throw new Error('The server returned an OTP response without a password field.');
    }
    return otp.password;
}
