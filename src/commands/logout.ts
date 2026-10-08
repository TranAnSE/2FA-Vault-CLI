/**
 * `2fav logout`
 *
 * Removes the stored PAT + host from both the OS keychain and the plaintext
 * fallback file. Safe to run even when nothing is stored.
 */

import { Command } from 'commander';
import * as keychain from '../services/keychain.js';

export const logoutCommand = new Command('logout')
    .description('Remove the stored 2FA-Vault credentials')
    .action(async () => {
        let removedSomething = false;

        if (await keychain.isAvailable()) {
            try {
                // Remove all entries (supports multi-instance); ignore misses.
                // Also purges any `--remember` derived-key cache entries.
                await keychain.remove();
                await keychain.removeAllDerivedKeys();
                removedSomething = true;
            } catch {
                /* fall through to fallback */
            }
        }

        if (await keychain.fallbackExists()) {
            await keychain.removeFallback();
            removedSomething = true;
        }

        if (removedSomething) {
            console.log('Logged out. Stored credentials removed.');
        } else {
            console.log('Nothing to log out — no stored credentials found.');
        }
    });
