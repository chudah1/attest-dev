/**
 * Core Attest verification logic, decoupled from MCP wiring.
 *
 * This module handles:
 *  - JWKS fetching and promise-cached refresh (handles key rotation)
 *  - Offline RS256 JWT verification via jose
 *  - Scope checking against att_scope claims
 *  - Revocation checking against the Attest server (fail-closed on timeout)
 */

import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { AttestClaims, JWKSResponse } from '@attest-dev/sdk';

// ── Types ────────────────────────────────────────────────────────────────────

export type DeniedCode =
  | 'missing_token'
  | 'invalid_token'
  | 'expired'
  | 'revoked'
  | 'scope_violation';

export interface DeniedReason {
  code: DeniedCode;
  tool: string;
  jti?: string;
  message: string;
}

export interface VerifyOptions {
  /** Base URL of the Attest server, e.g. "http://localhost:8080". */
  attestBaseUrl: string;
  /**
   * Full URL for the JWKS endpoint.
   * Defaults to `attestBaseUrl + "/.well-known/jwks.json"`.
   */
  jwksUrl?: string;
  /**
   * Pre-loaded JWKS to use instead of fetching. Useful for offline/test mode.
   * When provided the JWKS endpoint is never contacted.
   */
  staticJwks?: JWKSResponse;
  /** Whether to check the Attest revocation list. Default: true. */
  checkRevocation?: boolean;
  /**
   * Milliseconds to wait for the revocation check before failing closed.
   * Default: 500.
   */
  revocationTimeoutMs?: number;
  /**
   * Scope prefix applied to tool names.
   * Tool "send_email" → required scope "<prefix>:send_email".
   * Default: "tool".
   */
  scopePrefix?: string;
}

export interface VerifyTokenResult {
  allowed: true;
  claims: AttestClaims;
}

export interface DenyResult {
  allowed: false;
  reason: DeniedReason;
}

export type VerifyResult = VerifyTokenResult | DenyResult;

// ── JWKS cache ───────────────────────────────────────────────────────────────

/**
 * A per-instance promise cache so that concurrent callers don't fire multiple
 * simultaneous JWKS fetches (thundering-herd protection).
 */
export class JwksCache {
  private readonly url: string;
  /** Resolves to a jose key-set function once the fetch completes. */
  private pending: Promise<ReturnType<typeof createRemoteJWKSet>> | null = null;

  constructor(url: string) {
    this.url = url;
  }

  /** Return the cached key-set, fetching once if not yet available. */
  get(): Promise<ReturnType<typeof createRemoteJWKSet>> {
    if (!this.pending) {
      this.pending = this.fetch();
    }
    return this.pending;
  }

  /**
   * Discard the cache so the next call to get() triggers a fresh fetch.
   * Call this when verification fails with a key-not-found error.
   */
  invalidate(): void {
    this.pending = null;
  }

  private async fetch(): Promise<ReturnType<typeof createRemoteJWKSet>> {
    // jose's createRemoteJWKSet returns a function that lazily fetches and
    // caches the JWKS. We wrap it in our own promise so we can share a single
    // instance across concurrent callers.
    return createRemoteJWKSet(new URL(this.url));
  }
}

/**
 * Build a jose key-set from a static JWKSResponse object (no network call).
 * Round-trips through a data URL so jose can parse it without HTTP.
 */
function keySetFromStatic(
  jwks: JWKSResponse,
): ReturnType<typeof createRemoteJWKSet> {
  const encoded = encodeURIComponent(JSON.stringify(jwks));
  return createRemoteJWKSet(new URL(`data:application/json,${encoded}`));
}

// ── Scope helpers ─────────────────────────────────────────────────────────────

/**
 * Returns true if the granted scopes cover the required scope entry.
 *
 * Wildcard rules (mirrors isScopeSubset from @attest-dev/sdk but for a single
 * required entry so we can produce a precise error):
 *   - "*:*"           covers everything
 *   - "<prefix>:*"    covers all actions under that prefix
 *   - "<prefix>:<action>" must match exactly (after wildcard expansion)
 */
export function isScopeCovered(
  grantedScope: string[],
  requiredResource: string,
  requiredAction: string,
): boolean {
  for (const entry of grantedScope) {
    const colon = entry.indexOf(':');
    if (colon === -1) continue;
    const resource = entry.slice(0, colon);
    const action = entry.slice(colon + 1);

    const resourceOk = resource === '*' || resource === requiredResource;
    const actionOk = action === '*' || action === requiredAction;
    if (resourceOk && actionOk) return true;
  }
  return false;
}

// ── Revocation check ──────────────────────────────────────────────────────────

/**
 * Checks `GET /v1/revoked/{jti}` on the Attest server.
 * Returns true if the credential IS revoked.
 *
 * Fails closed: any network error or timeout → returns true (deny).
 */
async function isRevoked(
  attestBaseUrl: string,
  jti: string,
  timeoutMs: number,
): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const url = `${attestBaseUrl.replace(/\/$/, '')}/v1/revoked/${encodeURIComponent(jti)}`;
    const res = await fetch(url, { signal: controller.signal });

    // 200 → revoked, 404 → not revoked
    if (res.status === 404) return false;
    if (res.ok) return true;

    // Any unexpected non-404 response → fail closed
    return true;
  } catch {
    // Timeout or network failure → fail closed
    return true;
  } finally {
    clearTimeout(timer);
  }
}

// ── Main verifier ─────────────────────────────────────────────────────────────

export class AttestVerifier {
  private readonly opts: Required<
    Omit<VerifyOptions, 'staticJwks' | 'jwksUrl'>
  > & {
    jwksUrl: string;
    staticJwks?: JWKSResponse;
  };

  private readonly jwksCache: JwksCache | null;
  private readonly staticKeySet:
    | ReturnType<typeof createRemoteJWKSet>
    | null = null;

  constructor(options: VerifyOptions) {
    const base = options.attestBaseUrl.replace(/\/$/, '');
    const opts: Required<Omit<VerifyOptions, 'staticJwks' | 'jwksUrl'>> & {
      jwksUrl: string;
      staticJwks?: JWKSResponse;
    } = {
      attestBaseUrl: base,
      jwksUrl: options.jwksUrl ?? `${base}/.well-known/jwks.json`,
      checkRevocation: options.checkRevocation ?? true,
      revocationTimeoutMs: options.revocationTimeoutMs ?? 500,
      scopePrefix: options.scopePrefix ?? 'tool',
    };
    if (options.staticJwks !== undefined) opts.staticJwks = options.staticJwks;
    this.opts = opts;

    if (options.staticJwks) {
      this.jwksCache = null;
      this.staticKeySet = keySetFromStatic(options.staticJwks);
    } else {
      this.jwksCache = new JwksCache(this.opts.jwksUrl);
    }
  }

  /**
   * Verify a raw JWT token for a given tool name.
   *
   * Steps:
   *  1. Decode + verify RS256 signature and expiry using cached JWKS.
   *  2. Re-fetch JWKS once if key not found (key rotation).
   *  3. Scope check: does att_scope cover "<prefix>:<toolName>"?
   *  4. Revocation check (unless disabled).
   */
  async verify(token: string, toolName: string): Promise<VerifyResult> {
    // ── 1. Verify JWT signature & expiry ──────────────────────────────────────
    let claims: AttestClaims;
    try {
      claims = await this.verifyJwt(token);
    } catch (err) {
      const msg = String(err);
      const isExpired =
        msg.includes('exp') ||
        msg.toLowerCase().includes('expired') ||
        msg.toLowerCase().includes('"exp" claim timestamp check failed');

      return {
        allowed: false,
        reason: {
          code: isExpired ? 'expired' : 'invalid_token',
          tool: toolName,
          message: isExpired
            ? 'Token has expired'
            : `Token verification failed: ${msg}`,
        },
      };
    }

    const jti = claims.jti;

    // ── 2. Scope check ────────────────────────────────────────────────────────
    const requiredResource = this.opts.scopePrefix;
    const requiredAction = toolName;

    if (!isScopeCovered(claims.att_scope, requiredResource, requiredAction)) {
      const reason: DeniedReason = {
        code: 'scope_violation',
        tool: toolName,
        message: `Token does not grant scope "${requiredResource}:${requiredAction}"`,
      };
      if (jti !== undefined) reason.jti = jti;
      return {
        allowed: false,
        reason,
      };
    }

    // ── 3. Revocation check ───────────────────────────────────────────────────
    if (this.opts.checkRevocation && jti) {
      const revoked = await isRevoked(
        this.opts.attestBaseUrl,
        jti,
        this.opts.revocationTimeoutMs,
      );
      if (revoked) {
        return {
          allowed: false,
          reason: {
            code: 'revoked',
            tool: toolName,
            jti,
            message: `Credential ${jti} has been revoked`,
          },
        };
      }
    }

    return { allowed: true, claims };
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  private async verifyJwt(token: string): Promise<AttestClaims> {
    // Static (offline) mode: no JWKS cache.
    if (this.staticKeySet) {
      const { payload } = await jwtVerify(token, this.staticKeySet, {
        algorithms: ['RS256'],
      });
      return payload as unknown as AttestClaims;
    }

    // Dynamic mode: try cached JWKS, retry once on key-not-found errors.
    const cache = this.jwksCache!;

    try {
      const keySet = await cache.get();
      const { payload } = await jwtVerify(token, keySet, {
        algorithms: ['RS256'],
      });
      return payload as unknown as AttestClaims;
    } catch (err) {
      // Re-fetch JWKS if the error looks like a key rotation issue.
      if (isKeyNotFoundError(err)) {
        cache.invalidate();
        const freshKeySet = await cache.get();
        const { payload } = await jwtVerify(token, freshKeySet, {
          algorithms: ['RS256'],
        });
        return payload as unknown as AttestClaims;
      }
      throw err;
    }
  }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function isKeyNotFoundError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const msg = err.message.toLowerCase();
  return (
    msg.includes('no applicable key found') ||
    msg.includes('key not found') ||
    msg.includes('jwks') ||
    msg.includes('kid')
  );
}
