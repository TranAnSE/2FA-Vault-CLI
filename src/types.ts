/**
 * Shared TypeScript types for 2FA-Vault-CLI.
 *
 * These mirror the response shapes documented in the 2FA-Vault OpenAPI spec
 * (2FA-Vault-API/2fauth-api-latest.yaml) so the CLI stays in sync with the
 * backend contract.
 */

/** Stored credentials for the active 2FA-Vault instance. */
export interface ApiConfig {
    /** Base URL of the 2FA-Vault instance, e.g. `https://vault.example.com`. No trailing slash. */
    host: string;
    /** Personal Access Token (PAT) used as a Bearer token. */
    pat: string;
}

/**
 * A 2FA account as returned by `GET /api/v1/twofaccounts`.
 *
 * NOTE: `service` is nullable in the backend (some accounts only carry an
 * `account` label). Always treat it as optional when filtering or printing.
 */
export interface Account {
    id: number;
    service: string | null;
    account: string | null;
    otp_type: 'totp' | 'hotp' | 'steam' | string;
    icon?: string | null;
    digits?: number;
    algorithm?: string;
    period?: number | null;
    counter?: number | null;
    group_id?: number | null;
    last_used_at?: string | null;
    is_pinned?: boolean;
}

/**
 * Response envelope for `GET /api/v1/twofaccounts`.
 *
 * The backend returns a Laravel `ResourceCollection`, which wraps the array of
 * accounts under a top-level `data` key. We keep `data` optional so a bare
 * array response is also tolerated defensively.
 */
export interface AccountListResponse {
    data?: Account[];
}

/**
 * Response shape for `GET /api/v1/twofaccounts/{id}/otp`.
 *
 * The OTP password is always a top-level `password` field (a string of digits
 * or, for Steam, an alphanumeric code).
 */
export interface OtpResponse {
    password: string;
    otp_type: 'totp' | 'hotp' | 'steam' | string;
    generated_at?: number;
    period?: number | null;
    counter?: number | null;
}

/** Minimal shape of `GET /api/v1/user` used only to verify the PAT. */
export interface UserResponse {
    name?: string;
    email?: string;
    id?: number;
}

/**
 * An E2EE account as returned by `GET /api/v1/twofaccounts/encrypted`
 * (EncryptedTwoFAccountResource): carries the ciphertext envelope in
 * `secret` unconditionally — the server can never decrypt it.
 */
export interface EncryptedAccount {
    id: number;
    service: string | null;
    account: string | null;
    otp_type: 'totp' | 'hotp' | 'steamtotp' | string;
    /** JSON string: {"ciphertext":"b64","iv":"b64","authTag":"b64"}. */
    secret: string;
    encrypted: boolean;
    digits?: number;
    algorithm?: string;
    period?: number | null;
    counter?: number | null;
    group_id?: number | null;
    notes?: string | null;
    is_pinned?: boolean;
    recovery_codes?: string | null;
}

/** Response envelope for `GET /api/v1/twofaccounts/encrypted`. */
export interface EncryptedAccountListResponse {
    data?: EncryptedAccount[];
}
