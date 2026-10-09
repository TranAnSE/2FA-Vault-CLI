/**
 * OTP engine tests — TOTP/HOTP/Steam byte-parity against the PHP server stack
 * (spomky-labs/otphp + doctormckay/steam-totp, the implementations
 * TwoFAccount.php:515-536 delegates to) plus RFC 6238 known answers as a
 * third, independent anchor. See src/fixtures/otp-vectors.json for provenance.
 */
import { describe, it, expect } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { computeTotp, computeHotp, computeSteam, getTimeRemaining, normalizeAlgorithm, base32Decode } from '../otp.js';

const vectorsDir = join(import.meta.dir, '..', '..', 'fixtures');
const otpVectors = JSON.parse(readFileSync(join(vectorsDir, 'otp-vectors.json'), 'utf8')) as {
    totp: { secret: string; algorithm: string; digits: number; period: number; at: number; code: string }[];
    hotp: { secret: string; algorithm: string; digits: number; counter: number; code: string }[];
    steam: { secret: string; at: number; code: string }[];
};

describe('TOTP parity with the PHP server stack (otphp)', () => {
    it('reproduces every server-generated vector byte-identically', async () => {
        expect(otpVectors.totp.length).toBeGreaterThan(100);
        const pending: Promise<void>[] = [];
        for (const vector of otpVectors.totp) {
            pending.push(
                computeTotp(vector.secret, {
                    at: vector.at,
                    digits: vector.digits,
                    period: vector.period,
                    algorithm: vector.algorithm,
                }).then((code) => {
                    // Name the vector on mismatch.
                    if (code !== vector.code) {
                        throw new Error(
                            `TOTP mismatch: secret=${vector.secret.slice(0, 8)}… alg=${vector.algorithm} ` +
                                `digits=${vector.digits} period=${vector.period} t=${vector.at}: got ${code}, want ${vector.code}`,
                        );
                    }
                }),
            );
        }
        await Promise.all(pending);
    });

    it('matches the RFC 6238 SHA1/SHA256/SHA512 known answers', async () => {
        // RFC 6238 appendix B reference secrets (ASCII "1234567890…" padded to
        // the digest block size) and sample times. The 6-digit code is the
        // 8-digit reference value taken modulo 10^6 (LAST six digits).
        const cases: [string, string, number, string][] = [
            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 'SHA-1', 59, '287082'],
            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 'SHA-1', 1111111109, '081804'],
            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 'SHA-1', 1234567890, '005924'],
            ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 'SHA-1', 2000000000, '279037'],
            [
                'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====',
                'SHA-256',
                59,
                '119246',
            ],
            [
                'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====',
                'SHA-256',
                1111111109,
                '084774',
            ],
            [
                'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====',
                'SHA-256',
                1234567890,
                '819424',
            ],
            [
                'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=',
                'SHA-512',
                59,
                '693936',
            ],
            [
                'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=',
                'SHA-512',
                1111111109,
                '091201',
            ],
        ];
        for (const [secret, algorithm, at, expected] of cases) {
            expect(await computeTotp(secret, { at, algorithm })).toBe(expected);
        }
    });
});

describe('HOTP parity with the PHP server stack (otphp)', () => {
    it('reproduces every server-generated vector byte-identically', () => {
        expect(otpVectors.hotp.length).toBeGreaterThan(50);
        const pending: Promise<void>[] = [];
        for (const vector of otpVectors.hotp) {
            pending.push(
                computeHotp(vector.secret, {
                    counter: vector.counter,
                    digits: vector.digits,
                    algorithm: vector.algorithm,
                }).then((code) => {
                    expect(code).toBe(vector.code);
                }),
            );
        }
        return Promise.all(pending);
    });
});

describe('Steam OTP parity with the PHP server stack (steam-totp)', () => {
    it('reproduces every server-generated vector byte-identically', async () => {
        expect(otpVectors.steam.length).toBeGreaterThan(0);
        for (const vector of otpVectors.steam) {
            const code = await computeSteam(vector.secret, { at: vector.at });
            if (code !== vector.code) {
                throw new Error(
                    `Steam mismatch: secret=${vector.secret.slice(0, 8)}… t=${vector.at}: got ${code}, want ${vector.code}`,
                );
            }
        }
    });

    it('produces 5-char codes from the 26-char Steam alphabet', async () => {
        const code = await computeSteam(otpVectors.steam[0].secret, { at: otpVectors.steam[0].at });
        expect(code).toMatch(/^[23456789BCDFGHJKMNPQRTVWXY]{5}$/);
    });
});

describe('algorithm normalization (server stores lowercase, WebCrypto wants SHA-…)', () => {
    it('maps stored algorithm names to WebCrypto digests', () => {
        expect(normalizeAlgorithm('sha1')).toBe('SHA-1');
        expect(normalizeAlgorithm('SHA1')).toBe('SHA-1');
        expect(normalizeAlgorithm('sha256')).toBe('SHA-256');
        expect(normalizeAlgorithm('sha-512')).toBe('SHA-512');
        expect(normalizeAlgorithm(undefined)).toBe('SHA-1');
        expect(normalizeAlgorithm('')).toBe('SHA-1');
    });

    it('fails closed on digests WebCrypto cannot provide (e.g. md5)', () => {
        expect(() => normalizeAlgorithm('md5')).toThrow('Unsupported OTP algorithm: md5');
    });

    it('normalization does not change codes (sha1 ≡ SHA-1)', async () => {
        const vector = otpVectors.totp[0];
        expect(await computeTotp(vector.secret, { at: vector.at, algorithm: 'sha1' })).toBe(vector.code);
    });
});

describe('base32 decoding', () => {
    it('decodes RFC 4648 test vectors', () => {
        expect(Array.from(base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'))).toEqual(
            Array.from(new TextEncoder().encode('12345678901234567890')),
        );
        expect(Array.from(base32Decode('JBSWY3DPEHPK3PXP'))).toEqual([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef]);
    });

    it('ignores padding and case', () => {
        expect(Array.from(base32Decode('jbswy3dpehpk3pxp='))).toEqual(Array.from(base32Decode('JBSWY3DPEHPK3PXP')));
    });
});

describe('getTimeRemaining', () => {
    it('returns seconds left in the current period', () => {
        const remaining = getTimeRemaining(30);
        expect(remaining).toBeGreaterThanOrEqual(1);
        expect(remaining).toBeLessThanOrEqual(30);
    });
});
