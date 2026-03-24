/**
 * @attest-dev/sdk/mcp — Attest credential enforcement middleware for MCP servers.
 *
 * Wraps any MCP server instance and enforces Attest credential checking on
 * every tool call before the underlying handler executes.
 *
 * ## Two-line integration
 *
 * ```ts
 * import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
 * import { withAttest } from "@attest-dev/sdk/mcp";
 *
 * const server = new McpServer({ name: "my-tools", version: "1.0.0" });
 * const protectedServer = withAttest(server, {
 *   issuerUri: "https://api.attest.dev",
 * });
 *
 * // Register tools exactly as before — every call is now credential-gated.
 * protectedServer.tool("send_email", "Send an email", schema, handler);
 * ```
 *
 * ## How it works
 *
 * `withAttest` monkey-patches `server.tool()` so each registered handler is
 * wrapped with a credential check closure.  On every tool call the closure:
 *
 * 1. Extracts the Attest JWT from `extra.authInfo.token` (set by the MCP
 *    auth middleware) or `extra.meta?.attest_token`.
 * 2. Verifies the JWT offline against the issuer's JWKS (cached per TTL).
 * 3. Maps the tool name to a Attest scope string via `scopeForTool()`.
 * 4. Confirms the credential's `att_scope` covers the required scope.
 * 5. Calls the Attest revocation endpoint to confirm the JTI is still live.
 * 6. If all checks pass, executes the original handler.
 * 7. If any check fails, returns a structured `attest_violation` error.
 * 8. Fire-and-forgets an audit event to the Attest server regardless of
 *    outcome.
 */

import { createRemoteJWKSet, decodeJwt, jwtVerify } from 'jose';

// ── Minimal MCP SDK surface we depend on ─────────────────────────────────────
// We use structural typing so this file has no hard runtime dependency on
// @modelcontextprotocol/sdk.  The actual McpServer instance is passed in at
// runtime; we only need the shape of `tool()` and the handler extra argument.

/** Minimal shape of the auth info injected by the MCP auth middleware. */
interface McpAuthInfo {
  /** Raw bearer token string (the Attest JWT). */
  token: string;
  clientId?: string;
  scopes?: string[];
  expiresAt?: Date;
  extra?: Record<string, unknown>;
}

/** Minimal shape of the extra argument passed to every MCP tool handler. */
interface McpRequestExtra {
  /** Populated by MCP auth middleware from the Authorization header. */
  authInfo?: McpAuthInfo | undefined;
  /** Arbitrary metadata; agents may pass attest_token here explicitly. */
  meta?: Record<string, unknown> | undefined;
  signal?: AbortSignal;
  sessionId?: string;
  requestId?: string | number;
}

/** A single MCP content block (text, image, etc.). */
interface McpContentBlock {
  type: string;
  text?: string;
  [key: string]: unknown;
}

/** Return type of every MCP tool handler. */
interface McpCallToolResult {
  content: McpContentBlock[];
  isError?: boolean;
}

/**
 * Minimal interface for any object that behaves like an MCP server.
 * `withAttest` accepts anything with a `tool()` method.
 */
export interface McpServerLike {
  tool: (...args: unknown[]) => unknown;
  [key: string]: unknown;
}

// ── Public types ─────────────────────────────────────────────────────────────

/** The decoded Attest JWT claims threaded through the MCP request. */
export interface AttestContext {
  /** Unique identifier for this credential. */
  jti: string;
  /** Task tree ID shared across the entire delegation chain. */
  att_tid: string;
  /** Delegation depth (0 = root credential). */
  att_depth: number;
  /** Granted permission scopes in "resource:action" form. */
  att_scope: string[];
  /** Human user who initiated the task. */
  att_uid: string;
  /** Raw JWT string. */
  token: string;
}

/** Emitted to `onViolation` when a tool call is blocked. */
export interface ScopeViolationEvent {
  /** MCP tool name that was blocked. */
  toolName: string;
  /** Attest scope required by this tool. */
  requiredScope: string;
  /** Scopes actually present in the credential (empty if no credential). */
  grantedScope: string[];
  /** Violation category. */
  reason:
    | 'no_credential'
    | 'credential_expired'
    | 'credential_revoked'
    | 'scope_violation'
    | 'invalid_credential'
    | 'audit_failure';
  /** Credential JTI if available. */
  jti?: string;
  /** Task ID if available. */
  taskId?: string;
  /** ISO timestamp of the violation. */
  timestamp: string;
}

/**
 * Options for `withAttest`.
 */
export interface AttestMcpOptions {
  /**
   * URI of the Attest server used to fetch JWKS and check revocation.
   * @example "https://api.attest.dev"
   */
  issuerUri: string;

  /**
   * How long (in seconds) to cache the JWKS before re-fetching.
   * Longer values reduce latency; shorter values pick up key rotations faster.
   * @default 3600
   */
  jwksCacheTTL?: number;

  /**
   * When `true` (the default), tool calls without a valid Attest credential
   * are blocked and a `attest_violation` error is returned.
   *
   * When `false`, violations are logged via `onViolation` but the tool call
   * proceeds.  Useful for gradual rollouts or debugging.
   * @default true
   */
  requireCredential?: boolean;

  /**
   * Called synchronously when any scope check fails.
   * Use this to emit metrics, write logs, or trigger alerts.
   */
  onViolation?: (event: ScopeViolationEvent) => void;

  /**
   * Per-tool scope overrides.  Keys are exact MCP tool names; values are
   * Attest scope strings.  Overrides the automatic `scopeForTool()` mapping.
   *
   * @example
   * toolScopeMap: {
   *   "send_message": "gmail:send",
   *   "query_db":     "postgres:read",
   * }
   */
  toolScopeMap?: Record<string, string>;

  /**
   * How long (in seconds) to cache revocation status for each JTI.
   * Revocation is eventually consistent; a short TTL (5-30 s) balances
   * latency against revocation lag.  Set to 0 to disable caching.
   * @default 10
   */
  revocationCacheTTL?: number;

  /**
   * Called when an audit POST to the Attest server fails.
   * Receives the underlying error and the event payload that was not delivered.
   *
   * Use this to implement a retry queue, write to a fallback log, or page
   * on-call for compliance-critical deployments.
   *
   * If omitted, failures are surfaced via `onViolation` (with
   * `reason: "audit_failure"`) and, if that is also unset, via
   * `console.warn` — audit failures are never silently dropped.
   *
   * @example
   * ```ts
   * onAuditError: (err, event) => {
   *   retryQueue.push({ event, attempts: 0 });
   *   logger.error("audit delivery failed", { err, jti: event.jti });
   * }
   * ```
   */
  onAuditError?: (error: Error, event: AuditPayload) => void;
}

/** Structured error payload returned in the tool response body on violation. */
export interface AttestViolationError {
  error: 'attest_violation';
  reason: ScopeViolationEvent['reason'];
  detail: string;
  jti?: string;
  taskId?: string;
}

/**
 * Optional Attest-specific options passed as the final argument to
 * `protectedServer.tool()`.  The MCP SDK never sees this object — it is
 * extracted and consumed by the `withAttest` wrapper before forwarding
 * the remaining arguments.
 *
 * @example
 * ```ts
 * protectedServer.tool("gh_create_issue", schema, handler, {
 *   requiredScope: "github:write",
 * });
 * ```
 */
export interface AttestToolOptions {
  /**
   * Explicit Attest scope string required to call this tool.
   * Overrides the automatic `scopeForTool()` mapping.
   * Use this for non-standard tool names or when the auto-mapping would
   * produce a misleading scope.
   *
   * @example "github:write"
   * @example "stripe:charge"
   */
  requiredScope?: string;
}

// ── scopeForTool ──────────────────────────────────────────────────────────────

/**
 * Maps an MCP tool name to a Attest scope string using a convention-based
 * approach.  The tool name is split on the first underscore: the part before
 * becomes the action; the rest (joined with `:`) becomes the resource.
 *
 * Action aliases:
 * - `create`, `update`, `write`, `put`, `patch` → `write`
 * - `remove`, `destroy`                         → `delete`
 * - `run`, `invoke`                             → `execute`
 * - `get`, `fetch`, `list`, `search`, `query`   → `read`
 *
 * @example
 * scopeForTool("send_email")          // "email:send"
 * scopeForTool("read_file")           // "file:read"
 * scopeForTool("delete_calendar_event") // "calendar_event:delete"
 * scopeForTool("create_user")         // "user:write"
 * scopeForTool("run_query")           // "query:execute"
 */
export function scopeForTool(toolName: string, overrides?: Record<string, string>): string {
  if (overrides?.[toolName]) return overrides[toolName]!;

  const idx = toolName.indexOf('_');
  if (idx === -1) {
    // No underscore — treat the whole name as both resource and action.
    return `${toolName}:execute`;
  }

  const rawAction = toolName.slice(0, idx).toLowerCase();
  const resource = toolName.slice(idx + 1).toLowerCase();

  const action = normaliseAction(rawAction);
  return `${resource}:${action}`;
}

const ACTION_ALIASES: Record<string, string> = {
  // write
  create: 'write',
  update: 'write',
  put: 'write',
  patch: 'write',
  set: 'write',
  upsert: 'write',
  // delete
  remove: 'delete',
  destroy: 'delete',
  // execute
  run: 'execute',
  invoke: 'execute',
  call: 'execute',
  // read
  get: 'read',
  fetch: 'read',
  list: 'read',
  search: 'read',
  query: 'read',
  find: 'read',
  lookup: 'read',
};

function normaliseAction(raw: string): string {
  return ACTION_ALIASES[raw] ?? raw;
}

// ── JWKS cache ────────────────────────────────────────────────────────────────

type RemoteJWKSet = ReturnType<typeof createRemoteJWKSet>;

/**
 * Thin wrapper around `jose`'s `createRemoteJWKSet` that respects the
 * configured cache TTL.  A new key-set is created when the TTL expires,
 * which forces a JWKS re-fetch on the next verification.
 */
class JwksCache {
  private readonly issuerUri: string;
  private readonly ttlMs: number;
  private keySet: RemoteJWKSet | null = null;
  private createdAt = 0;

  constructor(issuerUri: string, ttlSeconds: number) {
    this.issuerUri = issuerUri.replace(/\/$/, '');
    this.ttlMs = ttlSeconds * 1000;
  }

  get(): RemoteJWKSet {
    const now = Date.now();
    if (this.keySet === null || now - this.createdAt > this.ttlMs) {
      this.keySet = createRemoteJWKSet(
        new URL(`${this.issuerUri}/.well-known/jwks.json`),
        // jose's internal cache is effectively bypassed by recreating the key
        // set on TTL expiry — fine for our use-case.
        { cacheMaxAge: this.ttlMs },
      );
      this.createdAt = now;
    }
    return this.keySet;
  }
}

// ── Revocation cache ──────────────────────────────────────────────────────────

interface RevocationEntry {
  revoked: boolean;
  expiresAt: number;
}

/**
 * Short-lived in-process cache for revocation status.
 * Reduces network calls to the Attest server on hot paths.
 */
class RevocationCache {
  private readonly cache = new Map<string, RevocationEntry>();
  private readonly ttlMs: number;
  private readonly issuerUri: string;

  constructor(issuerUri: string, ttlSeconds: number) {
    this.issuerUri = issuerUri.replace(/\/$/, '');
    this.ttlMs = ttlSeconds * 1000;
  }

  async isRevoked(jti: string): Promise<boolean> {
    const now = Date.now();
    const cached = this.cache.get(jti);
    if (cached !== undefined && now < cached.expiresAt) {
      return cached.revoked;
    }

    const revoked = await this.fetchRevocationStatus(jti);
    if (this.ttlMs > 0) {
      this.cache.set(jti, { revoked, expiresAt: now + this.ttlMs });
    }
    return revoked;
  }

  /** Evict a JTI immediately (e.g. after a revocation call). */
  evict(jti: string): void {
    this.cache.delete(jti);
  }

  private async fetchRevocationStatus(jti: string): Promise<boolean> {
    try {
      const res = await fetch(
        `${this.issuerUri}/v1/revoked/${encodeURIComponent(jti)}`,
      );
      if (!res.ok) return false; // fail-open on network error
      const body = (await res.json()) as { revoked?: boolean };
      return body.revoked === true;
    } catch {
      // Fail-open: don't block tools because the revocation endpoint is down.
      return false;
    }
  }
}

// ── Scope enforcement ─────────────────────────────────────────────────────────

/**
 * Attest JWT claims shape (subset required for enforcement).
 * Mirrors `AttestClaims` from `@attest-dev/sdk` without re-importing it here.
 */
interface WrtClaims {
  jti?: string;
  exp?: number;
  att_tid?: string;
  att_scope?: string[];
  att_depth?: number;
  att_uid?: string;
}

function isScopeGranted(grantedScope: string[], requiredScope: string): boolean {
  const [reqResource, reqAction] = requiredScope.split(':');
  if (!reqResource || !reqAction) return false;

  return grantedScope.some(entry => {
    const [resource, action] = entry.split(':');
    if (!resource || !action) return false;
    const resourceOk = resource === '*' || resource === reqResource;
    const actionOk = action === '*' || action === reqAction;
    return resourceOk && actionOk;
  });
}

// ── Token extraction ──────────────────────────────────────────────────────────

/**
 * Pulls the raw JWT string from an MCP tool call's `extra` argument.
 *
 * Lookup order:
 * 1. `extra.authInfo.token`       — set by the MCP auth middleware (preferred)
 * 2. `extra.meta.attest_token`   — explicit pass-through from the agent
 * 3. `extra.meta.authorization`   — raw "Bearer <token>" header value
 *
 * Returns `null` when no credential can be found.
 */
function extractToken(extra: McpRequestExtra): string | null {
  // 1. Standard MCP auth middleware path.
  if (extra.authInfo?.token) return extra.authInfo.token;

  const meta = extra.meta;
  if (!meta) return null;

  // 2. Explicit attest_token field.
  if (typeof meta['attest_token'] === 'string' && meta['attest_token']) {
    return meta['attest_token'];
  }

  // 3. Raw Authorization header forwarded via meta.
  if (typeof meta['authorization'] === 'string') {
    const auth = meta['authorization'];
    if (auth.startsWith('Bearer ')) return auth.slice(7).trim();
    return auth.trim() || null;
  }

  return null;
}

// ── Audit logging ─────────────────────────────────────────────────────────────

/**
 * The audit event payload sent to `POST /v1/audit` on the Attest server.
 * Passed to `onAuditError` when delivery fails so the caller can retry or
 * write to a fallback log.
 */
export interface AuditPayload {
  event_type: 'verified' | 'revoked';
  jti: string;
  att_tid?: string | undefined;
  att_uid?: string | undefined;
  agent_id: string;
  scope: string[];
  meta?: Record<string, string> | undefined;
}

/**
 * Fire-and-forget audit event to the Attest server.
 *
 * Delivery is async and never blocks the tool call.  On failure, errors are
 * surfaced in priority order:
 *   1. `onAuditError(error, payload)`   — caller handles retry / fallback log
 *   2. `onViolation({ reason: "audit_failure", ... })` — surfaces to monitoring
 *   3. `console.warn`                   — last resort, never silently dropped
 */
function fireAudit(
  issuerUri: string,
  payload: AuditPayload,
  onAuditError: ((error: Error, event: AuditPayload) => void) | undefined,
  onViolation: ((event: ScopeViolationEvent) => void) | undefined,
): void {
  void fetch(`${issuerUri}/v1/audit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
    .then(async (res) => {
      if (!res.ok) {
        // Non-2xx is also a delivery failure — treat it the same as a network error.
        let body = '';
        try { body = await res.text(); } catch { /* ignore */ }
        throw new Error(`Attest audit endpoint returned ${res.status}: ${body}`);
      }
    })
    .catch((err: unknown) => {
      const error = err instanceof Error ? err : new Error(String(err));

      if (onAuditError) {
        onAuditError(error, payload);
        return;
      }

      if (onViolation) {
        onViolation({
          toolName: payload.agent_id,
          requiredScope: '',
          grantedScope: payload.scope,
          reason: 'audit_failure',
          ...(payload.jti ? { jti: payload.jti } : {}),
          ...(payload.att_tid ? { taskId: payload.att_tid } : {}),
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // Last resort: never silently drop an audit failure.
      console.warn(
        '[attest] Audit delivery failed — configure onAuditError for structured handling.',
        { jti: payload.jti, agent_id: payload.agent_id, error: error.message },
      );
    });
}

// ── Core enforcer ─────────────────────────────────────────────────────────────

class AttestEnforcer {
  private readonly issuerUri: string;
  private readonly requireCredential: boolean;
  private readonly onViolation: ((event: ScopeViolationEvent) => void) | undefined;
  private readonly onAuditError: ((error: Error, event: AuditPayload) => void) | undefined;
  private readonly toolScopeMap: Record<string, string> | undefined;

  private readonly jwks: JwksCache;
  private readonly revocations: RevocationCache;

  constructor(opts: AttestMcpOptions) {
    this.issuerUri = opts.issuerUri.replace(/\/$/, '');
    this.requireCredential = opts.requireCredential ?? true;
    this.onViolation = opts.onViolation;
    this.onAuditError = opts.onAuditError;
    this.toolScopeMap = opts.toolScopeMap;
    this.jwks = new JwksCache(this.issuerUri, opts.jwksCacheTTL ?? 3600);
    this.revocations = new RevocationCache(this.issuerUri, opts.revocationCacheTTL ?? 10);
  }

  /**
   * Resolve the scope string for a tool, preferring an explicit override
   * over the automatic `scopeForTool()` mapping.
   */
  resolveScope(toolName: string, explicit?: string): string {
    return explicit ?? scopeForTool(toolName, this.toolScopeMap);
  }

  /**
   * Checks the credential in `extra` for `toolName`.
   *
   * @param resolvedScope Pre-resolved scope string (from `resolveScope`).
   * @returns `null` when the check passes; a `AttestViolationError` otherwise.
   */
  async check(
    toolName: string,
    extra: McpRequestExtra,
    resolvedScope: string,
  ): Promise<AttestViolationError | null> {
    const requiredScope = resolvedScope;
    const rawToken = extractToken(extra);

    // ── 1. No credential ────────────────────────────────────────────────────
    if (!rawToken) {
      return this.violate(toolName, {
        reason: 'no_credential',
        detail: `Tool "${toolName}" requires a Attest credential (scope: ${requiredScope}). Provide an Authorization: Bearer <token> header.`,
        requiredScope,
        grantedScope: [],
      });
    }

    // ── 2. Decode (without verification) to read claims for error messages ──
    let raw: WrtClaims;
    try {
      raw = decodeJwt(rawToken) as unknown as WrtClaims;
    } catch {
      return this.violate(toolName, {
        reason: 'invalid_credential',
        detail: 'The provided credential could not be decoded as a JWT.',
        requiredScope,
        grantedScope: [],
      });
    }

    const jti = raw.jti;
    const taskId = raw.att_tid;
    const grantedScope = raw.att_scope ?? [];

    // ── 3. Verify signature + expiry via JWKS ───────────────────────────────
    try {
      await jwtVerify(rawToken, this.jwks.get(), {
        algorithms: ['RS256'],
        requiredClaims: ['exp', 'jti'],
      });
    } catch (err) {
      const isExpiry =
        err instanceof Error && err.message.toLowerCase().includes('exp');
      return this.violate(toolName, {
        reason: isExpiry ? 'credential_expired' : 'invalid_credential',
        detail: isExpiry
          ? `Credential (jti: ${jti}) has expired.`
          : `Credential signature verification failed: ${String(err)}`,
        requiredScope,
        grantedScope,
        ...(jti !== undefined ? { jti } : {}),
        ...(taskId !== undefined ? { taskId } : {}),
      });
    }

    // ── 4. Scope check ──────────────────────────────────────────────────────
    if (!isScopeGranted(grantedScope, requiredScope)) {
      const result = this.violate(toolName, {
        reason: 'scope_violation',
        detail:
          `Credential (jti: ${jti}) grants [${grantedScope.join(', ')}] ` +
          `but tool "${toolName}" requires "${requiredScope}".`,
        requiredScope,
        grantedScope,
        ...(jti !== undefined ? { jti } : {}),
        ...(taskId !== undefined ? { taskId } : {}),
      });
      fireAudit(this.issuerUri, {
        event_type: 'verified',
        jti: jti ?? 'unknown',
        ...(taskId !== undefined ? { att_tid: taskId } : {}),
        ...(raw.att_uid !== undefined ? { att_uid: raw.att_uid } : {}),
        agent_id: `mcp:${toolName}`,
        scope: grantedScope,
        meta: { outcome: 'scope_violation', required_scope: requiredScope },
      }, this.onAuditError, this.onViolation);
      return result;
    }

    // ── 5. Revocation check ─────────────────────────────────────────────────
    if (jti) {
      const revoked = await this.revocations.isRevoked(jti);
      if (revoked) {
        const result = this.violate(toolName, {
          reason: 'credential_revoked',
          detail: `Credential (jti: ${jti}) has been revoked.`,
          requiredScope,
          grantedScope,
          jti,
          ...(taskId !== undefined ? { taskId } : {}),
        });
        fireAudit(this.issuerUri, {
          event_type: 'revoked',
          jti,
          ...(taskId !== undefined ? { att_tid: taskId } : {}),
          ...(raw.att_uid !== undefined ? { att_uid: raw.att_uid } : {}),
          agent_id: `mcp:${toolName}`,
          scope: grantedScope,
          meta: { outcome: 'blocked_revoked' },
        }, this.onAuditError, this.onViolation);
        return result;
      }
    }

    // ── 6. All checks passed — log and allow ────────────────────────────────
    fireAudit(this.issuerUri, {
      event_type: 'verified',
      jti: jti ?? 'unknown',
      ...(taskId !== undefined ? { att_tid: taskId } : {}),
      ...(raw.att_uid !== undefined ? { att_uid: raw.att_uid } : {}),
      agent_id: `mcp:${toolName}`,
      scope: grantedScope,
      meta: { outcome: 'allowed', required_scope: requiredScope },
    }, this.onAuditError, this.onViolation);
    return null;
  }

  private violate(
    toolName: string,
    opts: {
      reason: ScopeViolationEvent['reason'];
      detail: string;
      requiredScope: string;
      grantedScope: string[];
      jti?: string;
      taskId?: string;
    },
  ): AttestViolationError | null {
    const event: ScopeViolationEvent = {
      toolName,
      requiredScope: opts.requiredScope,
      grantedScope: opts.grantedScope,
      reason: opts.reason,
      timestamp: new Date().toISOString(),
      ...(opts.jti !== undefined ? { jti: opts.jti } : {}),
      ...(opts.taskId !== undefined ? { taskId: opts.taskId } : {}),
    };

    this.onViolation?.(event);

    if (!this.requireCredential) {
      // Permissive mode: log the violation but let the call through.
      return null;
    }

    return {
      error: 'attest_violation',
      reason: opts.reason,
      detail: opts.detail,
      ...(opts.jti !== undefined ? { jti: opts.jti } : {}),
      ...(opts.taskId !== undefined ? { taskId: opts.taskId } : {}),
    };
  }
}

// ── Scope registry ────────────────────────────────────────────────────────────

// Maps each patched server instance → its tool-name-to-scope registry.
// WeakMap so patched servers can be GC'd without leaking.
const scopeRegistries = new WeakMap<McpServerLike, Map<string, string>>();

// ── withAttest ───────────────────────────────────────────────────────────────

/**
 * Wraps an MCP server instance and enforces Attest credential checking on
 * every tool call.
 *
 * Returns the **same** server object with its `tool()` method patched in place,
 * typed as the original server type so all other methods remain accessible.
 *
 * @param server  Any object with a `tool()` method (e.g. `new McpServer(...)`).
 * @param options Attest enforcement options.
 * @returns       The patched server (same reference, same type).
 *
 * @example
 * ```ts
 * import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
 * import { withAttest } from "@attest-dev/sdk/mcp";
 *
 * const server = new McpServer({ name: "my-tools", version: "1.0.0" });
 * const protectedServer = withAttest(server, {
 *   issuerUri: "https://api.attest.dev",
 * });
 *
 * protectedServer.tool("send_email", schema, async (args, extra) => {
 *   // Only reached when the caller holds a valid credential
 *   // with "email:send" in its att_scope.
 *   return { content: [{ type: "text", text: "sent!" }] };
 * });
 * ```
 */
export function withAttest<T extends McpServerLike>(server: T, options: AttestMcpOptions): T {
  const enforcer = new AttestEnforcer(options);
  const registry = new Map<string, string>();
  scopeRegistries.set(server, registry);

  const originalTool = server.tool.bind(server) as (...args: unknown[]) => unknown;

  // Replace server.tool with our intercepting wrapper.
  // The MCP SDK's McpServer.tool() has two overloads:
  //   tool(name, schema, handler)
  //   tool(name, description, schema, handler)
  // We additionally support an optional trailing AttestToolOptions object:
  //   tool(name, schema, handler, { requiredScope: "..." })
  //   tool(name, description, schema, handler, { requiredScope: "..." })
  // That object is consumed here and stripped before forwarding to the SDK.
  server.tool = function attestTool(...args: unknown[]): unknown {
    const patched = patchToolArgs(enforcer, registry, args);
    return originalTool(...patched);
  };

  return server;
}

/**
 * Detects the handler function and optional trailing `AttestToolOptions` in
 * the `tool()` argument list, wraps the handler with credential enforcement,
 * strips the options object (the MCP SDK doesn't know about it), and returns
 * the patched argument array ready to forward to the original `tool()`.
 */
function patchToolArgs(
  enforcer: AttestEnforcer,
  registry: Map<string, string>,
  args: unknown[],
): unknown[] {
  if (args.length === 0) return args;

  // Detect optional trailing AttestToolOptions.
  // It's a plain object (not a function, not an array, not null) that may
  // carry { requiredScope?: string }.  The handler is always a function and
  // always comes before the options if options are present.
  let coreArgs = args;
  let explicitScope: string | undefined;

  const last = args[args.length - 1];
  if (
    last !== null &&
    typeof last === 'object' &&
    !Array.isArray(last) &&
    typeof (last as Record<string, unknown>)['requiredScope'] !== 'function'
  ) {
    // Candidate options object — check the one before it is a function.
    const penultimate = args[args.length - 2];
    if (typeof penultimate === 'function') {
      const opts = last as AttestToolOptions;
      explicitScope = opts.requiredScope;
      coreArgs = args.slice(0, -1); // strip options before forwarding
    }
  }

  const handlerArg = coreArgs[coreArgs.length - 1];
  if (typeof handlerArg !== 'function') return coreArgs;

  // Tool name is always the first argument.
  const toolName = typeof coreArgs[0] === 'string' ? coreArgs[0] : '<unknown>';

  // Resolve and record the scope for this tool.
  const resolvedScope = enforcer.resolveScope(toolName, explicitScope);
  registry.set(toolName, resolvedScope);

  const original = handlerArg as (
    params: unknown,
    extra: McpRequestExtra,
  ) => Promise<McpCallToolResult>;

  const wrapped = async (
    params: unknown,
    extra: McpRequestExtra,
  ): Promise<McpCallToolResult> => {
    const violation = await enforcer.check(toolName, extra, resolvedScope);

    if (violation !== null) {
      return {
        content: [{ type: 'text', text: JSON.stringify(violation, null, 2) }],
        isError: true,
      };
    }

    return original(params, extra);
  };

  Object.defineProperty(wrapped, 'name', { value: `attest:${toolName}` });

  return [...coreArgs.slice(0, -1), wrapped];
}

// ── Convenience re-export of AttestContext builder ───────────────────────────

/**
 * Decodes the Attest JWT in `extra` and returns a typed `AttestContext`
 * without performing any cryptographic verification.
 *
 * Useful inside tool handlers when you want to read the credential's claims
 * (e.g. `att_uid`, `att_tid`) after `withAttest` has already enforced them.
 *
 * @returns `null` when no Attest credential is present.
 *
 * @example
 * ```ts
 * protectedServer.tool("send_email", schema, async (args, extra) => {
 *   const ctx = getAttestContext(extra);
 *   console.log("acting on behalf of", ctx?.att_uid);
 *   ...
 * });
 * ```
 */
export function getAttestContext(extra: McpRequestExtra): AttestContext | null {
  const token = extractToken(extra);
  if (!token) return null;

  try {
    const claims = decodeJwt(token) as unknown as WrtClaims;
    return {
      jti: claims.jti ?? '',
      att_tid: claims.att_tid ?? '',
      att_depth: claims.att_depth ?? 0,
      att_scope: claims.att_scope ?? [],
      att_uid: claims.att_uid ?? '',
      token,
    };
  } catch {
    return null;
  }
}

/**
 * Returns the scope registry for a server that has been wrapped with
 * `withAttest` — a map of every registered tool name to its resolved
 * Attest scope string.
 *
 * Use this to build a scope discovery endpoint so credential issuers can
 * query what scopes a server requires without out-of-band coordination.
 *
 * @example
 * ```ts
 * // Express / Hono / any HTTP framework:
 * app.get("/.well-known/attest-scopes", (_req, res) => {
 *   res.json({ tools: getAttestScopes(protectedServer) });
 * });
 *
 * // Response:
 * // {
 * //   "tools": {
 * //     "send_email":      "email:send",
 * //     "read_file":       "file:read",
 * //     "gh_create_issue": "github:write"
 * //   }
 * // }
 * ```
 *
 * Tools that have not yet been registered (i.e. `server.tool()` hasn't been
 * called for them yet) will not appear in the result.  Call this after all
 * tools are registered, not during server startup.
 *
 * @returns A plain `Record<string, string>` safe to serialize directly as JSON.
 */
export function getAttestScopes(server: McpServerLike): Record<string, string> {
  const registry = scopeRegistries.get(server);
  if (!registry) return {};
  return Object.fromEntries(registry);
}
