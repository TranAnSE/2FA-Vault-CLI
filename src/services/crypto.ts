/**
 * Local E2EE crypto — decrypt 2FA-Vault vault secrets without the server.
 *
 * Byte-identical with the web app implementation
 * (`2FA-Vault/resources/js/services/crypto.js`):
 * - Argon2id key derivation (hash-wasm; same algorithm/params as argon2-browser)
 * - AES-256-GCM secret decryption via Web Crypto
 * - Vault unlock verification against the `VERIFICATION_TEST_VALUE` test value
 *
 * The three encodings that make or break parity (see CRYPTO_PARAMS docs):
 * 1. the salt is base64-DECODED before Argon2 (crypto.js:47),
 * 2. Argon2 memory cost is in KiB — 65536, not 64 (crypto.js:15),
 * 3. the AES-GCM input is ciphertext||authTag concatenated (crypto.js:117-120).
 *
 * A mismatch in any of these fails silently as a generic decryption error —
 * exactly like the web app (crypto.js:136). Keep it that way: no oracle that
 * distinguishes a bad envelope shape from a wrong password.
 */

/**
 * Crypto configuration shared with the web app (`crypto.js:14-29`).
 *
 * ARGON2 matches `ARGON2_CONFIG` in crypto.js: `time` = passes,
 * `memorySize` = KiB (64 MiB), `hashLength` = raw output bytes,
 * `parallelism` = lanes, Argon2id variant. AES matches `AES_CONFIG`:
 * 256-bit GCM key, 12-byte IV, 128-bit auth tag. The salt is 32 bytes,
 * base64-encoded at rest (`users.encryption_salt`).
 */
export const CRYPTO_PARAMS = {
    ARGON2: {
        iterations: 3,
        memorySize: 65_536,
        hashLength: 32,
        parallelism: 1,
    },
    AES: {
        name: 'AES-GCM',
        length: 256,
        ivLength: 12,
        tagLength: 128,
    },
    SALT_LENGTH: 32,
} as const;

/** The literal plaintext the web app seals as the vault test value (crypto.js:196). */
export const VERIFICATION_TEST_VALUE = 'VERIFICATION_TEST_VALUE';

/** Shape of an encrypted secret envelope as stored in `twofaccounts.secret`. */
export interface SecretEnvelope {
    ciphertext: string;
    iv: string;
    authTag: string;
}

/**
 * Derive the 32-byte vault key from the master password.
 *
 * Mirrors `crypto.js:45-64` up to (but excluding) the CryptoKey import: the
 * salt is base64-decoded first, then Argon2id runs with the shared params and
 * the RAW hash bytes are returned. Raw bytes (unlike the web app's
 * non-extractable CryptoKey) are what the `--remember` keychain cache needs.
 * Import them with `importAesKey` at the use site.
 *
 * @param masterPassword The vault master password (UTF-8 string).
 * @param saltBase64 The per-vault salt as stored in `users.encryption_salt`.
 */
export async function deriveKey(masterPassword: string, saltBase64: string): Promise<Uint8Array> {
    const saltBytes = base64ToBytes(saltBase64);
    if (saltBytes.length === 0) {
        throw new Error('Decryption failed: Invalid password or corrupted data');
    }

    // Lazy import keeps CLI cold start fast: argon2's WASM (64 MiB of memory
    // cost per call) is only needed on the unlock path, never for plain
    // server-OTP commands. hash-wasm was chosen over Bun.password because the
    // latter self-generates its salt and returns PHC strings — it cannot
    // reproduce the SPA's deterministic key (probe recorded 2026-10-08).
    const { argon2id } = await import('hash-wasm');

    return argon2id({
        password: masterPassword,
        salt: saltBytes,
        iterations: CRYPTO_PARAMS.ARGON2.iterations,
        memorySize: CRYPTO_PARAMS.ARGON2.memorySize,
        hashLength: CRYPTO_PARAMS.ARGON2.hashLength,
        parallelism: CRYPTO_PARAMS.ARGON2.parallelism,
        outputType: 'binary',
    });
}

/** Import raw derived-key bytes as a non-extractable AES-GCM CryptoKey (crypto.js:57-63). */
export async function importAesKey(keyBytes: Uint8Array): Promise<CryptoKey> {
    return crypto.subtle.importKey('raw', keyBytes, { name: CRYPTO_PARAMS.AES.name }, false, [
        'encrypt',
        'decrypt',
    ]);
}

/**
 * Decrypt a secret envelope. Mirrors `crypto.js:110-138`: base64-decode the
 * three fields, feed AES-GCM the ciphertext||authTag concatenation, decode
 * UTF-8. Every failure — wrong password, bad base64, truncated envelope —
 * surfaces as the same generic message (no password oracle).
 */
export async function decryptSecret(encryptedData: SecretEnvelope, key: CryptoKey): Promise<string> {
    try {
        const ciphertext = base64ToBytes(encryptedData.ciphertext);
        const iv = base64ToBytes(encryptedData.iv);
        const authTag = base64ToBytes(encryptedData.authTag);

        const combined = new Uint8Array(ciphertext.length + authTag.length);
        combined.set(ciphertext);
        combined.set(authTag, ciphertext.length);

        const plaintextBytes = await crypto.subtle.decrypt(
            {
                name: CRYPTO_PARAMS.AES.name,
                iv: iv,
                tagLength: CRYPTO_PARAMS.AES.tagLength,
            },
            key,
            combined,
        );

        return new TextDecoder().decode(plaintextBytes);
    } catch {
        throw new Error('Decryption failed: Invalid password or corrupted data');
    }
}

/**
 * Verify a derived key against the vault test value (`crypto.js:207-215`).
 * Returns false on any failure — never throws — so the unlock flow can
 * re-prompt without leaking why verification failed.
 */
export async function verifyTestValue(testValueJson: string, key: CryptoKey): Promise<boolean> {
    try {
        const envelope = JSON.parse(testValueJson) as SecretEnvelope;
        const plaintext = await decryptSecret(envelope, key);
        return plaintext === VERIFICATION_TEST_VALUE;
    } catch {
        return false;
    }
}

/** Convert bytes to standard-alphabet base64 (mirrors crypto.js:224-227). */
export function bytesToBase64(bytes: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/** Convert standard-alphabet base64 to bytes (mirrors crypto.js:234-237). */
export function base64ToBytes(base64: string): Uint8Array {
    const binString = atob(base64);
    const bytes = new Uint8Array(binString.length);
    for (let i = 0; i < binString.length; i++) {
        bytes[i] = binString.charCodeAt(i);
    }
    return bytes;
}
