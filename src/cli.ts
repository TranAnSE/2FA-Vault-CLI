#!/usr/bin/env bun
/**
 * 2FA-Vault CLI entry point.
 *
 * Wires the commander program, registers every Phase 1 command, and installs a
 * single global error handler that prints human-readable messages to stderr and
 * exits with a non-zero code on failure (CI-friendly).
 *
 * Phase 1 scope: API-only commands (login, logout, list, get, copy).
 * Phase 2 (E2EE / local crypto) is intentionally NOT wired here yet.
 */

import { program, CommanderError } from 'commander';
import { loginCommand } from './commands/login.js';
import { logoutCommand } from './commands/logout.js';
import { listCommand } from './commands/list.js';
import { getCommand } from './commands/get.js';
import { copyCommand } from './commands/copy.js';
import { CliError } from './services/api.js';
import pkg from '../package.json' with { type: 'json' };

// Single source of truth: read from package.json so the compiled binary and
// `npm/bun` metadata can never drift apart. Bumping the version in
// package.json is the only change needed for both `--version` and releases.
const VERSION = pkg.version;

program
    .name('2fav')
    .version(VERSION, '-v, --version', 'Print the 2fav version')
    .description('2FA-Vault CLI — manage your two-factor accounts from the terminal');

program.addCommand(loginCommand);
program.addCommand(logoutCommand);
program.addCommand(listCommand);
program.addCommand(getCommand);
program.addCommand(copyCommand);

/**
 * Run the program and handle errors uniformly. Commander throws `CommanderError`
 * for usage mistakes (e.g. missing required argument); our own commands throw
 * `CliError` for runtime/API failures. Both must result in a clean stderr
 * message and a non-zero exit — never an unhandled stack trace.
 */
export async function run(argv: string[]): Promise<void> {
    try {
        await program.parseAsync(argv, { from: 'user' });
    } catch (err) {
        if (err instanceof CliError) {
            fail(err.message, err.exitCode);
        }
        if (err instanceof CommanderError) {
            // commander already printed its own message; just mirror the code.
            process.exit(err.exitCode);
        }
        const detail = err instanceof Error ? err.message : String(err);
        fail(`Unexpected error: ${detail}`);
    }
}

/** Print a message to stderr and exit with the given code. */
function fail(message: string, code = 1): never {
    process.stderr.write(`Error: ${message}\n`);
    process.exit(code);
}

/**
 * Strip the two non-user argv tokens Bun always prepends, so commander's
 * `from: 'user'` parse receives only the real arguments.
 *
 * `bun run src/cli.ts` yields [bun, <script>, ...args]; a `--compile`d
 * standalone yields ["bun", "<virtual-root>/exe", ...args] (verified on
 * Windows and Linux — the first token is the literal string "bun" and the
 * second is the executable's virtual path). Passing either shape through
 * made commander treat "bun" as the command ("unknown command 'bun'");
 * `--version` masked it because program-level options are handled before
 * command resolution, which is why flag-only CI smoke tests stayed green.
 */
export function toUserArgs(argv: string[]): string[] {
    return argv.slice(2);
}

// Only execute when this file is the process entry (direct run or the
// compiled binary) — tests import toUserArgs and must not trigger a parse.
if (import.meta.main) {
    await run(toUserArgs(process.argv));
}
