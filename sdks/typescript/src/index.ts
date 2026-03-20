/**
 * @attest-dev/sdk — TypeScript client for the Attest credential service.
 *
 * Offline JWT verification uses `jose` (no network call needed after
 * fetchJWKS). All network calls go through the Attest server REST API.
 */

import {
  createRemoteJWKSet,
  jwtVerify,
  decodeJwt,
  type JWTPayload,
} from 'jose';

// ── Types ────────────────────────────────────────────────────────────────────

/** Standard JWT claims plus every att_* Attest extension. */
export interface AttestClaims extends JWTPayload {
  /** Task tree ID shared across the entire delegation chain. */
  att_tid: string;
  /** Parent credential jti (absent on root credentials). */
  att_pid?: string;
  /** Delegation depth (0 = root). */
  att_depth: number;
  /** Granted permission scopes in "resource:action" form. */
  att_scope: string[];
  /** SHA-256 hex of the original instruction that initiated the task. */
  att_intent: string;
  /** Ordered jti ancestry list from root to this credential. */
  att_chain: string[];
  /** Human principal who initiated the task. */
  att_uid: string;
}

/** A root credential returned by issue(). */
export interface AttestToken {
  token: string;
  claims: AttestClaims;
}

/** A delegated child credential returned by delegate(). */
export interface DelegatedToken {
  token: string;
  claims: AttestClaims;
}

/** Returned by verify(). Valid is false if any check fails. */
export interface VerifyResult {
  valid: boolean;
  claims?: AttestClaims;
  warnings: string[];
}

/** A complete audit trail for a task tree. */
export interface AuditChain {
  taskId: string;
  events: AuditEvent[];
}

/** A single entry in the audit log. */
export interface AuditEvent {
  id?: number;
  prev_hash: string;
  entry_hash: string;
  event_type: 'issued' | 'delegated' | 'verified' | 'revoked' | 'expired';
  jti: string;
  att_tid: string;
  att_uid: string;
  agent_id: string;
  scope: string[];
  meta?: Record<string, string>;
  created_at: string;
}

/** Subset of a JWKS response sufficient for RS256 verification. */
export interface JWKSResponse {
  keys: JWK[];
}

export interface JWK {
  kty: string;
  use?: string;
  alg?: string;
  n: string;
  e: string;
  kid?: string;
}

/** Parameters for issuing a root credential. */
export interface IssueParams {
  agent_id: string;
  user_id: string;
  scope: string[];
  instruction: string;
  ttl_seconds?: number;
}

/** Parameters for delegating to a child agent. */
export interface DelegateParams {
  parent_token: string;
  child_agent: string;
  child_scope: string[];
  ttl_seconds?: number;
}

// ── AttestClient ─────────────────────────────────────────────────────────────

export class AttestClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;

  constructor({ baseUrl = 'http://localhost:8080', apiKey }: { baseUrl?: string; apiKey: string }) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.headers = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
    };
  }

  /** Issue a root credential for the given agent and instruction. */
  async issue(params: IssueParams): Promise<AttestToken> {
    const res = await fetch(`${this.baseUrl}/v1/credentials`, {
      method: 'POST',
      headers: this.headers,
      body: JSON.stringify(params),
    });
    if (!res.ok) await throwFromResponse(res);
    return res.json() as Promise<AttestToken>;
  }

  /** Delegate a narrowed child credential from a parent token. */
  async delegate(params: DelegateParams): Promise<DelegatedToken> {
    const res = await fetch(`${this.baseUrl}/v1/credentials/delegate`, {
      method: 'POST',
      headers: this.headers,
      body: JSON.stringify(params),
    });
    if (!res.ok) await throwFromResponse(res);
    return res.json() as Promise<DelegatedToken>;
  }

  /**
   * Offline verification — validates RS256 signature, expiry, chain length
   * (must equal depth + 1), and chain tail (must equal jti).
   *
   * Pass a JWKSResponse previously fetched with fetchJWKS(). No network call
   * is made during verification itself.
   */
  async verify(token: string, jwks: JWKSResponse): Promise<VerifyResult> {
    const warnings: string[] = [];

    // Build a JWKS key source from the raw key objects by round-tripping
    // through a data URL so jose can parse it without a network request.
    const jwksData = JSON.stringify(jwks);
    const dataUrl = `data:application/json,${encodeURIComponent(jwksData)}`;

    let payload: AttestClaims;
    try {
      const keySet = createRemoteJWKSet(new URL(dataUrl));
      const { payload: raw } = await jwtVerify(token, keySet, {
        algorithms: ['RS256'],
      });
      payload = raw as unknown as AttestClaims;
    } catch (err) {
      return { valid: false, warnings: [`signature/expiry check failed: ${String(err)}`] };
    }

    // Chain length must equal depth + 1 (root depth=0 → chain=[jti]).
    const expectedLen = (payload.att_depth ?? 0) + 1;
    if (!payload.att_chain || payload.att_chain.length !== expectedLen) {
      warnings.push(
        `chain length ${payload.att_chain?.length} does not match depth ${payload.att_depth} (expected ${expectedLen})`,
      );
    }

    // Chain tail must match jti.
    const chain = payload.att_chain ?? [];
    if (chain.length > 0 && chain[chain.length - 1] !== payload.jti) {
      warnings.push(`chain tail "${chain[chain.length - 1]}" does not match jti "${payload.jti}"`);
    }

    return {
      valid: warnings.length === 0,
      claims: payload,
      warnings,
    };
  }

  /** Revoke a credential and cascade to all descendants. */
  async revoke(jti: string, revokedBy = 'sdk'): Promise<void> {
    const res = await fetch(`${this.baseUrl}/v1/credentials/${encodeURIComponent(jti)}`, {
      method: 'DELETE',
      headers: this.headers,
      body: JSON.stringify({ revoked_by: revokedBy }),
    });
    if (!res.ok && res.status !== 204) await throwFromResponse(res);
  }

  /** Fetch the full audit chain for a task tree. */
  async audit(taskId: string): Promise<AuditChain> {
    const res = await fetch(
      `${this.baseUrl}/v1/tasks/${encodeURIComponent(taskId)}/audit`,
      { headers: this.headers },
    );
    if (!res.ok) await throwFromResponse(res);
    const events = (await res.json()) as AuditEvent[];
    return { taskId, events };
  }

  /** Fetch the server's public key set for offline verification. */
  async fetchJWKS(): Promise<JWKSResponse> {
    const res = await fetch(`${this.baseUrl}/.well-known/jwks.json`, {
      headers: this.headers,
    });
    if (!res.ok) await throwFromResponse(res);
    return res.json() as Promise<JWKSResponse>;
  }
}

// ── Exported utilities ────────────────────────────────────────────────────────

/**
 * Returns true if every entry in childScope is covered by at least one entry
 * in parentScope. Wildcards ("*") match any resource or action.
 *
 * @example
 * isScopeSubset(["gmail:*"], ["gmail:send"])         // true
 * isScopeSubset(["gmail:send"], ["database:delete"]) // false
 */
export function isScopeSubset(parentScope: string[], childScope: string[]): boolean {
  for (const childEntry of childScope) {
    const child = parseScope(childEntry);
    if (!child) return false;

    const covered = parentScope.some(parentEntry => {
      const parent = parseScope(parentEntry);
      if (!parent) return false;
      const resourceOK = parent.resource === '*' || parent.resource === child.resource;
      const actionOK = parent.action === '*' || parent.action === child.action;
      return resourceOK && actionOK;
    });

    if (!covered) return false;
  }
  return true;
}

/**
 * Decodes a Attest JWT without verifying the signature.
 * Use verify() for trusted access to claims.
 */
export function decodeToken(token: string): AttestClaims {
  return decodeJwt(token) as unknown as AttestClaims;
}

// ── Internal helpers ──────────────────────────────────────────────────────────

interface ScopeEntry {
  resource: string;
  action: string;
}

function parseScope(s: string): ScopeEntry | null {
  const parts = s.split(':');
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  return { resource: parts[0], action: parts[1] };
}

async function throwFromResponse(res: Response): Promise<never> {
  let message = `HTTP ${res.status}`;
  try {
    const body = (await res.json()) as { error?: string };
    if (body.error) message += `: ${body.error}`;
  } catch {
    // ignore parse failure
  }
  throw new Error(message);
}
