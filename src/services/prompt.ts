/**
 * Interactive prompt helpers shared by `login` and the E2EE vault unlock.
 *
 * Mirrors the `login.ts` pattern: echo is muted on a real TTY; in a
 * non-interactive context (piped stdin) the value is read line-by-line from
 * stdin without prompting; when neither is available, an error is thrown.
 */

import { createInterface } from 'node:readline';
import { CliError } from './api.js';

/**
 * Prompt for a secret with muted echo. The value is never echoed, never
 * stored — callers consume the returned string immediately.
 */
export function promptHidden(label: string): Promise<string> {
    if (!process.stdin.isTTY) {
        // Non-interactive: read the first line of piped input.
        return new Promise<string>((resolve, reject) => {
            let data = '';
            process.stdin.setEncoding('utf8');
            process.stdin.on('data', (chunk) => {
                data += chunk;
                const nl = data.indexOf('\n');
                if (nl >= 0) {
                    process.stdin.removeAllListeners('data');
                    resolve(data.slice(0, nl).replace(/\r$/, '').trim());
                }
            });
            process.stdin.on('end', () => resolve(data.trim()));
            process.stdin.on('error', reject);
        });
    }

    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    // Mute echoed characters while typing. We only let newlines through so the
    // prompt stays on its own line; everything else is swallowed.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (rl as any)._writeToOutput = (s: string) => {
        if (s === '\r' || s === '\n') rl.write(s);
    };

    return new Promise<string>((resolve) => {
        rl.question(label, (answer) => {
            rl.close();
            console.log(''); // newline after the muted prompt
            resolve(answer.trim());
        });
    });
}

/**
 * Prompt for a required secret, erroring clearly when neither a TTY nor piped
 * stdin can provide one (scripts/CI without input).
 */
export async function promptHiddenRequired(label: string, missingInputMessage: string): Promise<string> {
    const value = await promptHidden(label);
    if (!value) {
        throw new CliError(missingInputMessage);
    }
    return value;
}
