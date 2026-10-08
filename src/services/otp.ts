/**
 * Local OTP computation — TOTP, HOTP and Steam OTP, dependency-free.
 *
 * Byte-identical with the rest of the ecosystem:
 * - TOTP/HOTP mirror the web app (`offline-totp.js:170-259`) and the
 *   extension (`e2eeCryptoService.js:100-160`): RFC 4648 base32 decode,
 *   8-byte big-endian counter, Web Crypto HMAC, dynamic truncation.
 * - Steam mirrors the server reference (`vendor/doctormckay/steam-totp/src/SteamTotp.php:9-32`):
 *   HMAC-SHA1, `& 0x7FFFFFFF`, 5 chars from a 26-char charset by repeated
 *   `fullcode % 26` — the secret input is base64 of the base32-decoded raw
 *   bytes, exactly what `TwoFAccount.php:535` feeds SteamTotp.
 */

/** Steam's alphabet — exactly 26 chars, do NOT substitute (SteamTotp.php:9). */
const STEAM_CHARSET = '23456789BCDFGHJKMNPQRTVWXY';
const STEAM_CODE_LENGTH = 5;

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export type OtpAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-512';

/** Options for TOTP computation. */
export interface TotpOptions {
    digits?: number;
    period?: number;
    algorithm?: string;
    /** Unix seconds to compute at (defaults to now). */
    at?: number;
}

/** Options for HOTP computation. */
export interface HotpOptions {
    counter: number;
    digits?: number;
    algorithm?: string;
}

/** Options for Steam OTP computation. */
export interface SteamOptions {
    /** Unix seconds to compute at (defaults to now). */
    at?: number;
}

/**
 * Normalize a stored algorithm name to a WebCrypto digest name.
 * The server persists lowercase (`TwoFAccount.php:452` mutator, constants
 * `sha1`/`sha256`/`sha512`); WebCrypto wants `SHA-1`-style. Mirrors the
 * extension's normalizer (`e2eeCryptoService.js:144-156`).
 */
export function normalizeAlgorithm(algorithm?: string | null): OtpAlgorithm {
    // Empty string defaults like the web app's falsy `account.algorithm || default`.
    const normalized = String(algorithm ?? '') === '' ? 'sha1' : String(algorithm).toLowerCase().replace(/-/g, '');
    if (normalized === 'sha1') return 'SHA-1';
    if (normalized === 'sha256') return 'SHA-256';
    if (normalized === 'sha512') return 'SHA-512';
    // The web app treats anything else as SHA-1 territory only via defaults;
    // for us an unknown digest (e.g. md5, unsupported by WebCrypto) fails
    // closed rather than silently producing a different code.
    throw new Error(`Unsupported OTP algorithm: ${algorithm}`);
}

/** RFC 4648 base32 decode (mirrors `offline-totp.js:225-247`). */
export function base32Decode(encoded: string): Uint8Array {
    const clean = encoded.toUpperCase().replace(/=+$/, '');

    let bits = 0;
    let value = 0;
    const output: number[] = [];

    for (let i = 0; i < clean.length; i++) {
        const idx = BASE32_CHARS.indexOf(clean[i]);
        if (idx === -1) continue;

        value = (value << 5) | idx;
        bits += 5;

        if (bits >= 8) {
            output.push((value >>> (bits - 8)) & 0xff);
            bits -= 8;
        }
    }

    return new Uint8Array(output);
}

/** Encode bytes as standard base64 (Steam's secret format, `TwoFAccount.php:535`). */
export function bytesToBase64(bytes: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/** Convert a counter to 8 big-endian bytes (mirrors `offline-totp.js:252-259`). */
function intToBytes(num: number): Uint8Array {
    const bytes = new Uint8Array(8);
    let n = num;
    for (let i = 7; i >= 0; i--) {
        bytes[i] = n & 0xff;
        n = Math.floor(n / 256);
    }
    return bytes;
}

/** HMAC-SHA1/256/512 over the counter bytes via Web Crypto. */
async function hmac(secretBytes: Uint8Array, counterBytes: Uint8Array, algorithm: OtpAlgorithm): Promise<Uint8Array> {
    const key = await crypto.subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: algorithm }, false, [
        'sign',
    ]);
    const signature = await crypto.subtle.sign({ name: 'HMAC', hash: algorithm }, key, counterBytes);
    return new Uint8Array(signature);
}

/** Dynamic truncation + digit encoding (mirrors `offline-totp.js:199-209`). */
function truncate(hmacBytes: Uint8Array, digits: number): string {
    const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
    const code =
        ((hmacBytes[offset] & 0x7f) << 24) |
        ((hmacBytes[offset + 1] & 0xff) << 16) |
        ((hmacBytes[offset + 2] & 0xff) << 8) |
        (hmacBytes[offset + 3] & 0xff);

    const modulo = Math.pow(10, digits);
    return (code % modulo).toString().padStart(digits, '0');
}

/** Shared HOTP core — both HOTP and TOTP are counter-based HMACs. */
async function hotpAt(
    secretBase32: string,
    counter: number,
    digits: number,
    algorithm: OtpAlgorithm,
): Promise<string> {
    const secretBytes = base32Decode(secretBase32);
    const mac = await hmac(secretBytes, intToBytes(counter), algorithm);
    return truncate(mac, digits);
}

/** Compute a TOTP code (mirrors `offline-totp.js:170-212`). */
export async function computeTotp(secretBase32: string, options: TotpOptions = {}): Promise<string> {
    const digits = options.digits ?? 6;
    const period = options.period ?? 30;
    const algorithm = normalizeAlgorithm(options.algorithm);
    const time = options.at ?? Math.floor(Date.now() / 1000);
    const counter = Math.floor(time / period);

    return hotpAt(secretBase32, counter, digits, algorithm);
}

/** Compute an HOTP code at an explicit counter. */
export async function computeHotp(secretBase32: string, options: HotpOptions): Promise<string> {
    const digits = options.digits ?? 6;
    const algorithm = normalizeAlgorithm(options.algorithm);

    return hotpAt(secretBase32, options.counter, digits, algorithm);
}

/**
 * Compute a Steam-style OTP (mirrors `SteamTotp.php:18-32`).
 * The account secret is base32 (as stored); SteamTotp receives base64 of the
 * decoded raw bytes — reproduce that hand-off exactly.
 */
export async function computeSteam(secretBase32: string, options: SteamOptions = {}): Promise<string> {
    const time = options.at ?? Math.floor(Date.now() / 1000);
    const secretBytes = base32Decode(secretBase32);
    const mac = await hmac(secretBytes, intToBytes(Math.floor(time / 30)), 'SHA-1');

    const offset = mac[mac.length - 1] & 0x0f;
    let fullCode =
        (((mac[offset] & 0x7f) << 24) |
            ((mac[offset + 1] & 0xff) << 16) |
            ((mac[offset + 2] & 0xff) << 8) |
            (mac[offset + 3] & 0xff)) >>>
        0; // keep unsigned before the division loop (PHP unpack 'N' is unsigned)
    fullCode = fullCode & 0x7fffffff;

    let code = '';
    for (let i = 0; i < STEAM_CODE_LENGTH; i++) {
        code += STEAM_CHARSET[fullCode % STEAM_CHARSET.length];
        fullCode = Math.floor(fullCode / STEAM_CHARSET.length);
    }

    return code;
}

/** Seconds remaining in the current TOTP period (mirrors `offline-totp.js:217-220`). */
export function getTimeRemaining(period = 30): number {
    const time = Math.floor(Date.now() / 1000);
    return period - (time % period);
}
