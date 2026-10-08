/**
 * Thin `fetch` wrapper around the 2FA-Vault REST API.
 *
 * - Reads host + PAT from the keychain (with plaintext-config fallback).
 * - Targets `{host}/api/v1`.
 * - Sends `Authorization: Bearer {PAT}` and `Accept: application/json`.
 * - Translates non-2xx responses into a clean, human-readable `CliError`
 *   (printed to stderr by the command layer, with a non-zero exit code).
 */

import * as keychain from './keychain.js';
import type { ApiConfig } from '../types.js';

/** CLI-domain error carrying an exit code (CI-friendly). */
export class CliError extends Error {
    readonly exitCode: number;
    /** HTTP status when the error came from an API response (0/undefined otherwise). */
    readonly status?: number;
    constructor(message: string, exitCode = 1, status?: number) {
        super(message);
        this.name = 'CliError';
        this.exitCode = exitCode;
        this.status = status;
    }
}

/** API base path on every 2FA-Vault instance. */
const API_PREFIX = '/api/v1';

/** Default per-request timeout (ms). */
const REQUEST_TIMEOUT_MS = 30_000;

/**
 * Resolve stored credentials. Prefers the OS keychain; falls back to the
 * plaintext config file. Throws a `CliError` when nothing is stored.
 */
export async function resolveCredentials(): Promise<ApiConfig> {
    if (await keychain.isAvailable()) {
        const creds = await keychain.get();
        if (creds) return creds;
    }
    const fallback = await keychain.getFallback();
    if (fallback) return fallback;
    throw new CliError('Not logged in. Run: 2fav login --host <URL>');
}

/**
 * Perform an authenticated GET against the API and return parsed JSON.
 *
 * @param path Path beginning with `/` (e.g. `/twofaccounts`).
 * @param init Extra fetch options (headers, query, etc.).
 */
export async function apiGet<T>(path: string, init: RequestInit = {}): Promise<T> {
    return apiRequest<T>(path, { ...init, method: 'GET' });
}

/** Perform an authenticated POST with a JSON body. */
export async function apiPost<T>(path: string, body: unknown, init: RequestInit = {}): Promise<T> {
    return apiRequest<T>(path, {
        ...init,
        method: 'POST',
        body: JSON.stringify(body),
        headers: { 'Content-Type': 'application/json', ...(init.headers ?? {}) },
    });
}

/** Perform an authenticated PATCH with a JSON body. */
export async function apiPatch<T>(path: string, body: unknown, init: RequestInit = {}): Promise<T> {
    return apiRequest<T>(path, {
        ...init,
        method: 'PATCH',
        body: JSON.stringify(body),
        headers: { 'Content-Type': 'application/json', ...(init.headers ?? {}) },
    });
}

/** Perform an authenticated request and parse the JSON body. */
export async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
    const creds = await resolveCredentials();
    const base = creds.host.replace(/\/+$/, '');
    const url = `${base}${API_PREFIX}${path.startsWith('/') ? path : `/${path}`}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    let res: Response;
    try {
        res = await fetch(url, {
            ...init,
            signal: init.signal ?? controller.signal,
            headers: {
                Authorization: `Bearer ${creds.pat}`,
                Accept: 'application/json',
                ...(init.headers ?? {}),
            },
        });
    } catch (err) {
        clearTimeout(timer);
        if (err instanceof Error && err.name === 'AbortError') {
            throw new CliError(`Request timed out after ${REQUEST_TIMEOUT_MS / 1000}s: ${url}`);
        }
        const detail = err instanceof Error ? err.message : String(err);
        throw new CliError(`Could not reach ${base}: ${detail}`);
    }
    clearTimeout(timer);

    if (!res.ok) {
        throw new CliError(await formatHttpError(res, path), 1, res.status);
    }

    const text = await res.text();
    if (!text) return undefined as unknown as T;
    try {
        return JSON.parse(text) as T;
    } catch {
        throw new CliError(`Received a non-JSON response from ${path}.`);
    }
}

/** Build a readable error string for a non-2xx response. */
async function formatHttpError(res: Response, path: string): Promise<string> {
    let serverMsg = '';
    try {
        const body: unknown = await res.clone().json();
        serverMsg =
            typeof body === 'object' && body !== null && 'message' in body && typeof (body as { message: unknown }).message === 'string'
                ? (body as { message: string }).message
                : JSON.stringify(body);
    } catch {
        /* body wasn't JSON */
    }
    const hint = authHint(res.status, path);
    const tail = serverMsg ? ` — ${serverMsg}` : '';
    return hint ? `${hint}${tail}` : `API error ${res.status} ${res.statusText}${tail}`;
}

/** Map common status codes to actionable hints. */
function authHint(status: number, path: string): string {
    // A failed vault verification is 401 but has nothing to do with the PAT
    // (the server answers `Verification failed` when the derived key does not
    // decrypt the stored test value) — the generic re-login hint mislabels it.
    if (status === 401 && path.startsWith('/encryption/verify')) {
        return 'Master password verification failed. The derived key does not match this vault.';
    }
    switch (status) {
        case 401:
            return 'Authentication failed (401). Your PAT may be invalid or revoked — run `2fav login` again.';
        case 403:
            return `Forbidden (403) for ${path}. Your PAT lacks the required scope.`;
        case 404:
            return `Not found (404): ${path}. Check the host URL and that the account exists.`;
        case 429:
            return 'Rate limited (429). Wait and try again.';
        default:
            return `API error ${status} for ${path}`;
    }
}
