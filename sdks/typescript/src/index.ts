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
import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';

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
  /** Verified Okta/OIDC issuer */
  att_idp_iss?: string;
  /** Verified Okta/OIDC subject/user ID */
  att_idp_sub?: string;
  /** HITL approval challenge/request ID */
  att_hitl_req?: string;
  /** HITL approver's verified IdP subject */
  att_hitl_uid?: string;
  /** HITL approver's verified IdP issuer */
  att_hitl_iss?: string;
  /** Agent checksum */
  att_ack?: string;
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
  event_type: 'issued' | 'delegated' | 'verified' | 'revoked' | 'expired' | 'hitl_granted' | 'action' | 'lifecycle';
  jti: string;
  att_tid: string;
  att_uid: string;
  agent_id: string;
  scope: string[];
  meta?: Record<string, string>;
  idp_issuer?: string;
  idp_subject?: string;
  hitl_req?: string;
  hitl_subject?: string;
  hitl_issuer?: string;
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

export interface EvidenceOrg {
  id: string;
  name: string;
}

export interface EvidenceTask {
  att_tid: string;
  root_jti: string;
  root_agent_id: string;
  att_uid: string;
  instruction_hash?: string;
  depth_max: number;
  credential_count: number;
  event_count: number;
  revoked: boolean;
}

export interface EvidenceApproval {
  present: boolean;
  request_id?: string;
  issuer?: string;
  subject?: string;
}

export interface EvidenceIdentity {
  user_id: string;
  idp_issuer?: string;
  idp_subject?: string;
  approval?: EvidenceApproval;
}

export interface EvidenceCredential {
  jti: string;
  parent_jti?: string;
  agent_id: string;
  scope: string[];
  depth: number;
  issued_at: string;
  expires_at: string;
  chain: string[];
  intent_hash?: string;
  agent_checksum?: string;
  idp_issuer?: string;
  idp_subject?: string;
  hitl_request_id?: string;
  hitl_subject?: string;
  hitl_issuer?: string;
}

export interface EvidenceIntegrity {
  audit_chain_valid: boolean;
  hash_algorithm: string;
  packet_hash: string;
  signature_algorithm?: string;
  signature_kid?: string;
  packet_signature?: string;
  notes: string[];
}

export interface EvidenceSummary {
  result: string;
  scope_violations: number;
  approvals: number;
  revocations: number;
}

export interface EvidencePacket {
  packet_type: string;
  schema_version: string;
  generated_at: string;
  org: EvidenceOrg;
  task: EvidenceTask;
  identity: EvidenceIdentity;
  credentials: EvidenceCredential[];
  events: AuditEvent[];
  integrity: EvidenceIntegrity;
  summary: EvidenceSummary;
}

export interface EvidencePacketVerifyResult {
  valid: boolean;
  hashValid: boolean;
  signatureValid: boolean;
  auditChainValid: boolean;
  warnings: string[];
}

/** Parameters for issuing a root credential. */
export interface IssueParams {
  agent_id: string;
  user_id: string;
  scope: string[];
  instruction: string;
  ttl_seconds?: number;
  id_token?: string;
  agent_checksum?: string;
}

/** Parameters for delegating to a child agent. */
export interface DelegateParams {
  parent_token: string;
  child_agent: string;
  child_scope: string[];
  ttl_seconds?: number;
}

/** An active human-in-the-loop approval challenge. */
export interface ApprovalChallenge {
  challenge_id: string;
  status: 'pending' | 'approved' | 'rejected';
}

/** Status of a polled approval request. */
export interface ApprovalStatus {
  id: string;
  agent_id: string;
  att_tid: string;
  intent: string;
  requested_scope: string[];
  status: 'pending' | 'approved' | 'rejected';
  approved_by?: string;
  created_at: string;
  resolved_at?: string;
}

/** A task summary returned by the list tasks endpoint. */
export interface TaskSummary {
  att_tid: string;
  att_uid: string;
  root_agent_id: string;
  event_count: number;
  credential_count: number;
  created_at: string;
  last_event_at: string;
  last_event_type: string;
  revoked: boolean;
}

/** Query parameters for listing tasks. */
export interface TaskListParams {
  userId?: string;
  agentId?: string;
  status?: 'active' | 'revoked';
  limit?: number;
}

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

// ── AttestClient ─────────────────────────────────────────────────────────────

export class AttestClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;
  private readonly timeoutMs: number;

  constructor({ baseUrl = 'http://localhost:8080', apiKey, timeoutMs = 30_000 }: { baseUrl?: string; apiKey: string; timeoutMs?: number }) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.timeoutMs = timeoutMs;
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
      signal: AbortSignal.timeout(this.timeoutMs),
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
      signal: AbortSignal.timeout(this.timeoutMs),
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
        requiredClaims: ['exp', 'jti'],
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
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok && res.status !== 204) await throwFromResponse(res);
  }

  /** Report an agent lifecycle event (started, completed, failed). */
  async reportStatus(params: {
    token: string;
    status: 'started' | 'completed' | 'failed';
    meta?: Record<string, string>;
  }): Promise<void> {
    const res = await fetch(`${this.baseUrl}/v1/audit/status`, {
      method: 'POST',
      headers: this.headers,
      body: JSON.stringify(params),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok && res.status !== 204) await throwFromResponse(res);
  }

  /** Report an action outcome against a credential for the audit trail. */
  async reportAction(params: {
    token: string;
    tool: string;
    outcome: string;
    meta?: Record<string, string>;
  }): Promise<void> {
    const res = await fetch(`${this.baseUrl}/v1/audit/report`, {
      method: 'POST',
      headers: this.headers,
      body: JSON.stringify(params),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok && res.status !== 204) await throwFromResponse(res);
  }

  /** Fetch the full audit chain for a task tree. */
  async audit(taskId: string): Promise<AuditChain> {
    const res = await fetch(
      `${this.baseUrl}/v1/tasks/${encodeURIComponent(taskId)}/audit`,
      { headers: this.headers, signal: AbortSignal.timeout(this.timeoutMs) },
    );
    if (!res.ok) await throwFromResponse(res);
    const events = (await res.json()) as AuditEvent[];
    return { taskId, events };
  }

  /** Fetch the canonical evidence packet for a task tree. */
  async fetchEvidence(taskId: string): Promise<EvidencePacket> {
    const res = await fetch(
      `${this.baseUrl}/v1/tasks/${encodeURIComponent(taskId)}/evidence`,
      { headers: this.headers, signal: AbortSignal.timeout(this.timeoutMs) },
    );
    if (!res.ok) await throwFromResponse(res);
    return res.json() as Promise<EvidencePacket>;
  }

  /** Fetch the org's public key set for offline signature verification. */
  async fetchJWKS(orgId: string): Promise<JWKSResponse> {
    const res = await fetch(`${this.baseUrl}/orgs/${encodeURIComponent(orgId)}/jwks.json`, {
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok) await throwFromResponse(res);
    return res.json() as Promise<JWKSResponse>;
  }

  /**
   * Offline verification for a signed evidence packet.
   *
   * Checks packet hash, packet signature, and audit prev_hash linkage.
   */
  async verifyEvidencePacket(packet: EvidencePacket, jwks: JWKSResponse): Promise<EvidencePacketVerifyResult> {
    return verifyEvidencePacketAgainstJWKS(packet, jwks);
  }

  /** Request human approval for a high-risk delegation. */
  async requestApproval(params: {
    parent_token: string;
    agent_id: string;
    att_tid: string;
    intent: string;
    requested_scope: string[];
  }): Promise<ApprovalChallenge> {
    const res = await fetch(`${this.baseUrl}/v1/approvals`, {
      method: 'POST',
      headers: this.headers,
      body: JSON.stringify(params),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok) await throwFromResponse(res);
    return res.json() as Promise<ApprovalChallenge>;
  }

  /** Poll the status of an approval request. */
  async getApproval(challengeId: string): Promise<ApprovalStatus> {
    const res = await fetch(
      `${this.baseUrl}/v1/approvals/${encodeURIComponent(challengeId)}`,
      { headers: this.headers, signal: AbortSignal.timeout(this.timeoutMs) },
    );
    if (!res.ok) await throwFromResponse(res);
    return res.json() as Promise<ApprovalStatus>;
  }

  /** Grant a pending approval and receive the HITL-authorized credential. */
  async grantApproval(challengeId: string, idToken: string): Promise<DelegatedToken> {
    const res = await fetch(
      `${this.baseUrl}/v1/approvals/${encodeURIComponent(challengeId)}/grant`,
      {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify({ id_token: idToken }),
        signal: AbortSignal.timeout(this.timeoutMs),
      },
    );
    if (!res.ok) await throwFromResponse(res);
    return res.json() as Promise<DelegatedToken>;
  }

  /** Deny a pending approval request. */
  async denyApproval(challengeId: string): Promise<{ id: string; status: string }> {
    const res = await fetch(
      `${this.baseUrl}/v1/approvals/${encodeURIComponent(challengeId)}/deny`,
      {
        method: 'POST',
        headers: this.headers,
        body: '{}',
        signal: AbortSignal.timeout(this.timeoutMs),
      },
    );
    if (!res.ok) await throwFromResponse(res);
    return res.json() as Promise<{ id: string; status: string }>;
  }

  /** List task summaries with optional filters. */
  async listTasks(params?: TaskListParams): Promise<TaskSummary[]> {
    const query = new URLSearchParams();
    if (params?.userId) query.set('user_id', params.userId);
    if (params?.agentId) query.set('agent_id', params.agentId);
    if (params?.status) query.set('status', params.status);
    if (params?.limit != null) query.set('limit', String(params.limit));
    const qs = query.toString();
    const res = await fetch(
      `${this.baseUrl}/v1/tasks${qs ? `?${qs}` : ''}`,
      { headers: this.headers, signal: AbortSignal.timeout(this.timeoutMs) },
    );
    if (!res.ok) await throwFromResponse(res);
    return res.json() as Promise<TaskSummary[]>;
  }
}

// ── AttestVerifier ────────────────────────────────────────────────────────────

/**
 * Stateless verifier for services that receive Attest credentials.
 * No API key required — only the org ID of the issuing organisation.
 *
 * @example
 * const verifier = new AttestVerifier({ orgId: 'org_abc123' });
 * const result = await verifier.verify(req.headers.authorization.slice(7));
 * if (!result.valid) throw new Error('Unauthorized');
 */
export class AttestVerifier {
  private readonly orgId: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private jwksCache: JWKSResponse | null = null;

  constructor({ orgId, baseUrl = 'https://api.attestdev.com', timeoutMs = 30_000 }: { orgId: string; baseUrl?: string; timeoutMs?: number }) {
    this.orgId = orgId;
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.timeoutMs = timeoutMs;
  }

  /**
   * Verify a token fully:
   *  1. Fetch (and cache) the org's JWKS
   *  2. Validate RS256 signature and expiry
   *  3. Check chain integrity (length and tail)
   *  4. Check revocation status against the server
   */
  async verify(token: string): Promise<VerifyResult> {
    const warnings: string[] = [];

    // 1. Fetch JWKS (cached after first call)
    if (!this.jwksCache) {
      const res = await fetch(`${this.baseUrl}/orgs/${encodeURIComponent(this.orgId)}/jwks.json`, {
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (!res.ok) return { valid: false, warnings: [`failed to fetch JWKS: HTTP ${res.status}`] };
      this.jwksCache = await res.json() as JWKSResponse;
    }

    // 2. Verify signature and expiry (retry once with fresh JWKS on failure)
    let payload: AttestClaims;
    let retried = false;
    while (true) {
      const jwksData = JSON.stringify(this.jwksCache);
      const dataUrl = `data:application/json,${encodeURIComponent(jwksData)}`;
      try {
        const keySet = createRemoteJWKSet(new URL(dataUrl));
        const { payload: raw } = await jwtVerify(token, keySet, {
          algorithms: ['RS256'],
          requiredClaims: ['exp', 'jti'],
        });
        payload = raw as unknown as AttestClaims;
        break;
      } catch (err) {
        if (!retried) {
          // Clear cache and refetch JWKS before retrying
          this.jwksCache = null;
          const res = await fetch(`${this.baseUrl}/orgs/${encodeURIComponent(this.orgId)}/jwks.json`, {
            signal: AbortSignal.timeout(this.timeoutMs),
          });
          if (!res.ok) return { valid: false, warnings: [`failed to refresh JWKS: HTTP ${res.status}`] };
          this.jwksCache = await res.json() as JWKSResponse;
          retried = true;
          continue;
        }
        return { valid: false, warnings: [`signature/expiry check failed: ${String(err)}`] };
      }
    }

    // 3. Chain integrity
    const expectedLen = (payload.att_depth ?? 0) + 1;
    if (!payload.att_chain || payload.att_chain.length !== expectedLen) {
      warnings.push(
        `chain length ${payload.att_chain?.length} does not match depth ${payload.att_depth} (expected ${expectedLen})`,
      );
    }
    const chain = payload.att_chain ?? [];
    if (chain.length > 0 && chain[chain.length - 1] !== payload.jti) {
      warnings.push(`chain tail does not match jti`);
    }

    // 4. Revocation check
    if (payload.jti) {
      try {
        const revRes = await fetch(
          `${this.baseUrl}/v1/revoked/${encodeURIComponent(payload.jti)}`,
          { signal: AbortSignal.timeout(this.timeoutMs) },
        );
        if (!revRes.ok) {
          return { valid: false, claims: payload, warnings: [...warnings, `revocation check failed: HTTP ${revRes.status}`] };
        }
        const { revoked } = await revRes.json() as { revoked: boolean };
        if (revoked) {
          return { valid: false, claims: payload, warnings: [...warnings, 'credential has been revoked'] };
        }
      } catch (err) {
        return { valid: false, claims: payload, warnings: [...warnings, `revocation server unreachable: ${String(err)}`] };
      }
    }

    return { valid: warnings.length === 0, claims: payload, warnings };
  }

  /** Verify a signed evidence packet using the verifier's cached org JWKS. */
  async verifyEvidencePacket(packet: EvidencePacket): Promise<EvidencePacketVerifyResult> {
    if (!this.jwksCache) {
      const res = await fetch(`${this.baseUrl}/orgs/${encodeURIComponent(this.orgId)}/jwks.json`, {
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (!res.ok) {
        return {
          valid: false,
          hashValid: false,
          signatureValid: false,
          auditChainValid: false,
          warnings: [`failed to fetch JWKS: HTTP ${res.status}`],
        };
      }
      this.jwksCache = await res.json() as JWKSResponse;
    }

    return verifyEvidencePacketAgainstJWKS(packet, this.jwksCache);
  }

  /** Clear the cached JWKS (call this to force a key refresh). */
  clearJWKSCache(): void {
    this.jwksCache = null;
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
  const idx = s.indexOf(':');
  if (idx < 1 || idx === s.length - 1) return null;
  return { resource: s.slice(0, idx), action: s.slice(idx + 1) };
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

function decodeBase64Url(value: string): Buffer {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + padding, 'base64');
}

function canonicalizeEvidencePacket(packet: EvidencePacket): string {
  const clone = JSON.parse(JSON.stringify(packet)) as Record<string, unknown>;
  const integrity = (clone.integrity ?? {}) as Record<string, unknown>;
  clone.integrity = integrity;
  integrity.packet_hash = '';
  delete integrity.signature_algorithm;
  delete integrity.signature_kid;
  delete integrity.packet_signature;
  return JSON.stringify(clone);
}

function validateAuditEvents(events: AuditEvent[]): string[] {
  const warnings: string[] = [];
  if (events.length === 0) return warnings;

  if (events[0]?.prev_hash !== GENESIS_HASH) {
    warnings.push('first audit event does not use the genesis previous hash');
  }

  for (let i = 1; i < events.length; i += 1) {
    const prev = events[i - 1];
    const current = events[i];
    if (prev && current && current.prev_hash !== prev.entry_hash) {
      warnings.push(`audit chain break between event ${prev.id ?? i} and ${current.id ?? i + 1}`);
    }
  }

  return warnings;
}

function verifyEvidencePacketAgainstJWKS(packet: EvidencePacket, jwks: JWKSResponse): EvidencePacketVerifyResult {
  const warnings: string[] = [];
  const canonicalJson = canonicalizeEvidencePacket(packet);
  const computedHash = createHash('sha256').update(canonicalJson).digest('hex');

  const hashValid = computedHash === packet.integrity.packet_hash;
  if (!hashValid) {
    warnings.push(`packet hash mismatch: expected ${packet.integrity.packet_hash}, computed ${computedHash}`);
  }

  let signatureValid = false;
  if (!packet.integrity.signature_algorithm || !packet.integrity.signature_kid || !packet.integrity.packet_signature) {
    warnings.push('packet signature metadata missing');
  } else if (packet.integrity.signature_algorithm !== 'RS256') {
    warnings.push(`unsupported signature algorithm: ${packet.integrity.signature_algorithm}`);
  } else {
    const jwk = jwks.keys.find((key) => key.kid === packet.integrity.signature_kid) ?? jwks.keys[0];
    if (!jwk) {
      warnings.push('no verification key found in JWKS');
    } else {
      try {
        const publicKey = createPublicKey({ key: jwk as any, format: 'jwk' });
        signatureValid = verifySignature(
          'RSA-SHA256',
          Buffer.from(canonicalJson, 'utf8'),
          publicKey,
          decodeBase64Url(packet.integrity.packet_signature),
        );
        if (!signatureValid) warnings.push('packet signature verification failed');
      } catch (err) {
        warnings.push(`packet signature verification failed: ${String(err)}`);
      }
    }
  }

  const auditWarnings = validateAuditEvents(packet.events);
  warnings.push(...auditWarnings);
  const auditChainValid = packet.integrity.audit_chain_valid && auditWarnings.length === 0;
  if (!packet.integrity.audit_chain_valid && auditWarnings.length === 0) {
    warnings.push('packet reports invalid audit chain');
  }

  return {
    valid: hashValid && signatureValid && auditChainValid,
    hashValid,
    signatureValid,
    auditChainValid,
    warnings,
  };
}
