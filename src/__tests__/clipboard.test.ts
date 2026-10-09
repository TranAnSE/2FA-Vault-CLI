/**
 * Unit tests for the clipboard dispatch.
 *
 * Platform is controlled by mocking `node:os` (the dispatch reads `platform()`
 * on every call). The actual process spawn is controlled by overriding the
 * `globalThis.Bun.spawn` property, since clipboard.ts runs under Bun and uses
 * the `runViaBun` branch. The real `Bun.spawn` is restored after each test.
 */

import { test, expect, mock, beforeEach, afterEach, afterAll } from 'bun:test';

// ---- in-memory records of what Bun.spawn did ----

interface SpawnRecord {
    cmd: string;
    args: string[];
    stdinInput: string;
    exitCode: number;
    error?: Error;
}

/** The shape clipboard.ts consumes from Bun.spawn (plain functions — the
 * in-memory fakes must not force Mock<> onto mockImplementationOnce payloads). */
interface SpawnResult {
    stdin: {
        getWriter: () => { write: (input: Uint8Array) => Promise<void>; close: () => Promise<void> };
    };
    stdout: 'ignore';
    stderr: 'ignore';
    exited: Promise<number>;
    exitCode: number;
}

let spawnLog: SpawnRecord[] = [];

const fakeWriter = {
    write: mock((input: Uint8Array) => {
        const rec = spawnLog[spawnLog.length - 1];
        if (rec) rec.stdinInput = new TextDecoder().decode(input);
        return Promise.resolve();
    }),
    close: mock(() => Promise.resolve()),
};

const fakeBunSpawn = mock((opts: { cmd: string[] }): SpawnResult => {
    const [cmd, ...args] = opts.cmd;
    const rec: SpawnRecord = { cmd, args, stdinInput: '', exitCode: 0 };
    spawnLog.push(rec);
    return {
        stdin: { getWriter: () => fakeWriter },
        stdout: 'ignore' as const,
        stderr: 'ignore' as const,
        exited: Promise.resolve(0),
        get exitCode() {
            return rec.exitCode;
        },
    };
});

// `globalThis.Bun` itself is a readonly binding, but its `spawn` property is
// writable. Override just that one method (clipboard.ts reads `Bun.spawn`),
// and restore the real one after the file's tests finish.
const bunGlobal = globalThis as { Bun: { spawn: unknown } };
const REAL_SPAWN = bunGlobal.Bun.spawn;
bunGlobal.Bun.spawn = fakeBunSpawn;

afterAll(() => {
    bunGlobal.Bun.spawn = REAL_SPAWN;
});

// Mock `node:os` so we can flip the platform per test.
const fakeOs = {
    platform: mock(() => 'linux' as NodeJS.Platform),
    homedir: mock(() => '/tmp/fake-home'),
};
mock.module('node:os', () => fakeOs);

// Import after mocks are registered.
const clipboard = await import('../services/clipboard.js');

beforeEach(() => {
    spawnLog = [];
    fakeBunSpawn.mockClear();
    fakeWriter.write.mockClear();
    fakeWriter.close.mockClear();
    fakeOs.platform.mockClear();
});

afterEach(() => {
    // Keep our mock active for the suite; only restore at process teardown.
    bunGlobal.Bun.spawn = fakeBunSpawn;
});

function setPlatform(p: 'darwin' | 'win32' | 'linux') {
    fakeOs.platform.mockImplementation(() => p as NodeJS.Platform);
}

/** Make the next spawned process "fail": the awaited stdin write rejects. */
function failNextSpawn() {
    fakeBunSpawn.mockImplementationOnce((opts: { cmd: string[] }) => {
        const [cmd, ...args] = opts.cmd;
        const err = new Error(`spawn ${cmd} failed`);
        spawnLog.push({
            cmd,
            args,
            stdinInput: '',
            exitCode: -1,
            error: err,
        });
        return {
            stdin: {
                getWriter: () => ({
                    write: () => Promise.reject(err),
                    close: () => Promise.resolve(),
                }),
            },
            stdout: 'ignore' as const,
            stderr: 'ignore' as const,
            // Resolve normally so no unhandled rejection leaks; the error is
            // surfaced via the awaited writer.write() above.
            exited: Promise.resolve(1),
            exitCode: 1,
        };
    });
}

// ---- tests ----

test('darwin: copyToClipboard runs `pbcopy` and writes the payload to stdin', async () => {
    setPlatform('darwin');
    const ok = await clipboard.copyToClipboard('123456');
    expect(ok).toBe(true);
    expect(spawnLog.length).toBe(1);
    expect(spawnLog[0].cmd).toBe('pbcopy');
    expect(spawnLog[0].args).toEqual([]);
    expect(spawnLog[0].stdinInput).toBe('123456');
});

test('win32: copyToClipboard runs `clip.exe`', async () => {
    setPlatform('win32');
    const ok = await clipboard.copyToClipboard('999111');
    expect(ok).toBe(true);
    expect(spawnLog[0].cmd).toBe('clip.exe');
    expect(spawnLog[0].args).toEqual([]);
});

test('linux: copyToClipboard prefers `xclip -selection clipboard`', async () => {
    setPlatform('linux');
    const ok = await clipboard.copyToClipboard('042042');
    expect(ok).toBe(true);
    expect(spawnLog[0].cmd).toBe('xclip');
    expect(spawnLog[0].args).toEqual(['-selection', 'clipboard']);
});

test('linux: falls back to `xsel` when xclip errors', async () => {
    setPlatform('linux');
    failNextSpawn(); // first spawn (xclip) errors

    const ok = await clipboard.copyToClipboard('555666');
    expect(ok).toBe(true);
    const attempted = spawnLog.map((r) => r.cmd);
    expect(attempted).toContain('xclip');
    expect(attempted).toContain('xsel');
});

test('copyToClipboard returns false when the process exits non-zero on all attempts', async () => {
    setPlatform('darwin');
    failNextSpawn(); // single platform with no fallbacks -> fails outright

    const ok = await clipboard.copyToClipboard('000000');
    expect(ok).toBe(false);
});

test('clipboardBackendLabel() reports the resolved command for the platform', () => {
    setPlatform('darwin');
    expect(clipboard.clipboardBackendLabel()).toBe('pbcopy');

    setPlatform('win32');
    expect(clipboard.clipboardBackendLabel()).toBe('clip.exe');

    setPlatform('linux');
    expect(clipboard.clipboardBackendLabel()).toBe('xclip');
});
