#!/usr/bin/env bun
/**
 * Compiled-binary runtime probe (RT-14).
 *
 * The release binaries are cross-compiled; a build-only smoke cannot prove the
 * bundled WASM (hash-wasm Argon2id) instantiates on the target platform. This
 * probe is compiled with the same `--compile` pipeline and prints the derived
 * key hex for a (password, salt) pair, so CI can execute the binary on a real
 * linux runner and compare against a committed parity vector.
 *
 * Usage: 2fav-probe <password> <saltBase64>
 */

import { deriveKey } from '../src/services/crypto.js';

const [password, saltBase64] = process.argv.slice(2);
if (!password || !saltBase64) {
    console.error('usage: 2fav-probe <password> <saltBase64>');
    process.exit(2);
}

const key = await deriveKey(password, saltBase64);
process.stdout.write(Array.from(key, (b) => b.toString(16).padStart(2, '0')).join('') + '\n');
