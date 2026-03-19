/**
 * @warrant/mcp — Warrant credential enforcement middleware for MCP servers.
 *
 * Wraps any MCP server instance and enforces Warrant credential checking on
 * every tool call before the underlying handler executes.
 *
 * ## Two-line integration
 *
 * ```ts
 * import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
 * import { withWarrant } from "@warrant/sdk/mcp";
 *
 * const server = new McpServer({ name: "my-tools", version: "1.0.0" });
 * const protectedServer = withWarrant(server, {
 *   issuerUri: "https://api.warrant.dev",
 * });
 *
 * // Register tools exactly as before — every call is now credential-gated.
 * protectedServer.tool("send_email", "Send an email", schema, handler);
 * ```
 *
 * ## How it works
 *
 * `withWarrant` monkey-patches `server.tool()` so each registered handler is
 * wrapped with a credential check closure.  On every tool call the closure:
 *
 * 1. Extracts the Warrant JWT from `extra.authInfo.token` (set by the MCP
 *    auth middleware) or `extra.meta?.warrant_token`.
 * 2. Verifies the JWT offline against the issuer's JWKS (cached per TTL).
 * 3. Maps the tool name to a Warrant scope string via `scopeForTool()`.
 * 4. Confirms the credential's `wrt_scope` covers the required scope.
 * 5. Calls the Warrant revocation endpoint to confirm the JTI is still live.
 * 6. If all checks pass, executes the original handler.
 * 7. If any check fails, returns a structured `warrant_violation` error.
 * 8. Fire-and-forgets an audit event to the Warrant server regardless of
 *    outcome.
 */

import { createRemoteJWKSet, decodeJwt, jwtVerify } from 'jose';

// ── Minimal MCP SDK surface we depend on ─────────────────────────────────────
// We use structural typing so this file has no hard runtime dependency on
// @modelcontextprotocol/sdk.  The actual McpServer instance is passed in at
// runtime; we only need the shape of `tool()` and the handler extra argument.

/** Minimal shape of the auth info injected by the MCP auth middleware. */
interface McpAuthInfo {
  /** Raw bearer token string (the Warrant JWT). */
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
  /** Arbitrary metadata; agents may pass warrant_token here explicitly. */
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
 * `withWarrant` accepts anything with a `tool()` method.
 */
export interface McpServerLike {
  tool: (...args: unknown[]) => unknown;
  [key: string]: unknown;
}

// ── Public types ─────────────────────────────────────────────────────────────

/** The decoded Warrant JWT claims threaded through the MCP request. */
export interface WarrantContext {
  /** Unique identifier for this credential. */
  jti: string;
  /** Task tree ID shared across the entire delegation chain. */
  wrt_tid: string;
  /** Delegation depth (0 = root credential). */
  wrt_depth: number;
  /** Granted permission scopes in "resource:action" form. */
  wrt_scope: string[];
  /** Human user who initiated the task. */
  wrt_uid: string;
  /** Raw JWT string. */
  token: string;
}

/** Emitted to `onViolation` when a tool call is blocked. */
export interface ScopeViolationEvent {
  /** MCP tool name that was blocked. */
  toolName: string;
  /** Warrant scope required by this tool. */
  requiredScope: string;
  /** Scopes actually present in the credential (empty if no credential). */
  grantedScope: string[];
  /** Violation category. */
  reason:
    | 'no_credential'
    | 'credential_expired'
    | 'credential_revoked'
    | 'scope_violation'
    | 'invalid_credential';
  /** Credential JTI if available. */
  jti?: string;
  /** Task ID if available. */
  taskId?: string;
  /** ISO timestamp of the violation. */
  timestamp: string;
}

/**
 * Options for `withWarrant`.
 */
export interface WarrantMcpOptions {
  /**
   * URI of the Warrant server used to fetch JWKS and check revocation.
   * @example "https://api.warrant.dev"
   */
  issuerUri: string;

  /**
   * How long (in seconds) to cache the JWKS before re-fetching.
   * Longer values reduce latency; shorter values pick up key rotations faster.
   * @default 3600
   */
  jwksCacheTTL?: number;

  /**
   * When `true` (the default), tool calls without a valid Warrant credential
   * are blocked and a `warrant_violation` error is returned.
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
   * Warrant scope strings.  Overrides the automatic `scopeForTool()` mapping.
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
}

/** Structured error payload returned in the tool response body on violation. */
export interface WarrantViolationError {
  error: 'warrant_violation';
  reason: ScopeViolationEvent['reason'];
  detail: string;
  jti?: string;
  taskId?: string;
}

// ── scopeForTool ──────────────────────────────────────────────────────────────

/**
 * Maps an MCP tool name to a Warrant scope string using a convention-based
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
 * Reduces network calls to the Warrant server on hot paths.
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
 * Warrant JWT claims shape (subset required for enforcement).
 * Mirrors `WarrantClaims` from `@warrant/sdk` without re-importing it here.
 */
interface WrtClaims {
  jti?: string;
  exp?: number;
  wrt_tid?: string;
  wrt_scope?: string[];
  wrt_depth?: number;
  wrt_uid?: string;
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
 * 2. `extra.meta.warrant_token`   — explicit pass-through from the agent
 * 3. `extra.meta.authorization`   — raw "Bearer <token>" header value
 *
 * Returns `null` when no credential can be found.
 */
function extractToken(extra: McpRequestExtra): string | null {
  // 1. Standard MCP auth middleware path.
  if (extra.authInfo?.token) return extra.authInfo.token;

  const meta = extra.meta;
  if (!meta) return null;

  // 2. Explicit warrant_token field.
  if (typeof meta['warrant_token'] === 'string' && meta['warrant_token']) {
    return meta['warrant_token'];
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

interface AuditPayload {
  event_type: 'verified' | 'revoked';
  jti: string;
  wrt_tid?: string | undefined;
  wrt_uid?: string | undefined;
  agent_id: string;
  scope: string[];
  meta?: Record<string, string> | undefined;
}

/**
 * Fire-and-forget audit event to the Warrant server.
 * Failures are silently swallowed — audit must never block tool execution.
 */
function fireAudit(issuerUri: string, payload: AuditPayload): void {
  // Intentionally not awaited.
  void fetch(`${issuerUri}/v1/audit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  }).catch(() => {
    // Swallow — audit is best-effort.
  });
}

// ── Core enforcer ─────────────────────────────────────────────────────────────

class WarrantEnforcer {
  private readonly issuerUri: string;
  private readonly requireCredential: boolean;
  private readonly onViolation: ((event: ScopeViolationEvent) => void) | undefined;
  private readonly toolScopeMap: Record<string, string> | undefined;

  private readonly jwks: JwksCache;
  private readonly revocations: RevocationCache;

  constructor(opts: WarrantMcpOptions) {
    this.issuerUri = opts.issuerUri.replace(/\/$/, '');
    this.requireCredential = opts.requireCredential ?? true;
    this.onViolation = opts.onViolation;
    this.toolScopeMap = opts.toolScopeMap;
    this.jwks = new JwksCache(this.issuerUri, opts.jwksCacheTTL ?? 3600);
    this.revocations = new RevocationCache(this.issuerUri, opts.revocationCacheTTL ?? 10);
  }

  /**
   * Checks the credential in `extra` for `toolName`.
   *
   * @returns `null` when the check passes; a `WarrantViolationError` otherwise.
   */
  async check(
    toolName: string,
    extra: McpRequestExtra,
  ): Promise<WarrantViolationError | null> {
    const requiredScope = scopeForTool(toolName, this.toolScopeMap);
    const rawToken = extractToken(extra);

    // ── 1. No credential ────────────────────────────────────────────────────
    if (!rawToken) {
      return this.violate(toolName, {
        reason: 'no_credential',
        detail: `Tool "${toolName}" requires a Warrant credential (scope: ${requiredScope}). Provide an Authorization: Bearer <token> header.`,
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
    const taskId = raw.wrt_tid;
    const grantedScope = raw.wrt_scope ?? [];

    // ── 3. Verify signature + expiry via JWKS ───────────────────────────────
    try {
      await jwtVerify(rawToken, this.jwks.get(), { algorithms: ['RS256'] });
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
        ...(taskId !== undefined ? { wrt_tid: taskId } : {}),
        ...(raw.wrt_uid !== undefined ? { wrt_uid: raw.wrt_uid } : {}),
        agent_id: `mcp:${toolName}`,
        scope: grantedScope,
        meta: { outcome: 'scope_violation', required_scope: requiredScope },
      });
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
          ...(taskId !== undefined ? { wrt_tid: taskId } : {}),
          ...(raw.wrt_uid !== undefined ? { wrt_uid: raw.wrt_uid } : {}),
          agent_id: `mcp:${toolName}`,
          scope: grantedScope,
          meta: { outcome: 'blocked_revoked' },
        });
        return result;
      }
    }

    // ── 6. All checks passed — log and allow ────────────────────────────────
    fireAudit(this.issuerUri, {
      event_type: 'verified',
      jti: jti ?? 'unknown',
      ...(taskId !== undefined ? { wrt_tid: taskId } : {}),
      ...(raw.wrt_uid !== undefined ? { wrt_uid: raw.wrt_uid } : {}),
      agent_id: `mcp:${toolName}`,
      scope: grantedScope,
      meta: { outcome: 'allowed', required_scope: requiredScope },
    });
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
  ): WarrantViolationError | null {
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
      error: 'warrant_violation',
      reason: opts.reason,
      detail: opts.detail,
      ...(opts.jti !== undefined ? { jti: opts.jti } : {}),
      ...(opts.taskId !== undefined ? { taskId: opts.taskId } : {}),
    };
  }
}

// ── withWarrant ───────────────────────────────────────────────────────────────

/**
 * Wraps an MCP server instance and enforces Warrant credential checking on
 * every tool call.
 *
 * Returns the **same** server object with its `tool()` method patched in place,
 * typed as the original server type so all other methods remain accessible.
 *
 * @param server  Any object with a `tool()` method (e.g. `new McpServer(...)`).
 * @param options Warrant enforcement options.
 * @returns       The patched server (same reference, same type).
 *
 * @example
 * ```ts
 * import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
 * import { withWarrant } from "@warrant/sdk/mcp";
 *
 * const server = new McpServer({ name: "my-tools", version: "1.0.0" });
 * const protectedServer = withWarrant(server, {
 *   issuerUri: "https://api.warrant.dev",
 * });
 *
 * protectedServer.tool("send_email", schema, async (args, extra) => {
 *   // Only reached when the caller holds a valid credential
 *   // with "email:send" in its wrt_scope.
 *   return { content: [{ type: "text", text: "sent!" }] };
 * });
 * ```
 */
export function withWarrant<T extends McpServerLike>(server: T, options: WarrantMcpOptions): T {
  const enforcer = new WarrantEnforcer(options);
  const originalTool = server.tool.bind(server) as (...args: unknown[]) => unknown;

  // Replace server.tool with our intercepting wrapper.
  // The MCP SDK's McpServer.tool() has two overloads:
  //   tool(name, schema, handler)
  //   tool(name, description, schema, handler)
  // We detect which form is used by checking whether the last argument is a
  // function, then wrap that handler.
  server.tool = function warrantTool(...args: unknown[]): unknown {
    const patched = patchToolArgs(enforcer, args);
    return originalTool(...patched);
  };

  return server;
}

/**
 * Finds the handler function in the tool() argument list (always the last
 * argument), wraps it with credential enforcement, and returns the patched
 * argument array.
 */
function patchToolArgs(enforcer: WarrantEnforcer, args: unknown[]): unknown[] {
  if (args.length === 0) return args;

  const lastArg = args[args.length - 1];
  if (typeof lastArg !== 'function') return args;

  // The tool name is always the first argument.
  const toolName = typeof args[0] === 'string' ? args[0] : '<unknown>';

  const original = lastArg as (
    params: unknown,
    extra: McpRequestExtra,
  ) => Promise<McpCallToolResult>;

  const wrapped = async (
    params: unknown,
    extra: McpRequestExtra,
  ): Promise<McpCallToolResult> => {
    const violation = await enforcer.check(toolName, extra);

    if (violation !== null) {
      return {
        content: [{ type: 'text', text: JSON.stringify(violation, null, 2) }],
        isError: true,
      };
    }

    return original(params, extra);
  };

  // Preserve the function's name for debugging.
  Object.defineProperty(wrapped, 'name', { value: `warrant:${toolName}` });

  return [...args.slice(0, -1), wrapped];
}

// ── Convenience re-export of WarrantContext builder ───────────────────────────

/**
 * Decodes the Warrant JWT in `extra` and returns a typed `WarrantContext`
 * without performing any cryptographic verification.
 *
 * Useful inside tool handlers when you want to read the credential's claims
 * (e.g. `wrt_uid`, `wrt_tid`) after `withWarrant` has already enforced them.
 *
 * @returns `null` when no Warrant credential is present.
 *
 * @example
 * ```ts
 * protectedServer.tool("send_email", schema, async (args, extra) => {
 *   const ctx = getWarrantContext(extra);
 *   console.log("acting on behalf of", ctx?.wrt_uid);
 *   ...
 * });
 * ```
 */
export function getWarrantContext(extra: McpRequestExtra): WarrantContext | null {
  const token = extractToken(extra);
  if (!token) return null;

  try {
    const claims = decodeJwt(token) as unknown as WrtClaims;
    return {
      jti: claims.jti ?? '',
      wrt_tid: claims.wrt_tid ?? '',
      wrt_depth: claims.wrt_depth ?? 0,
      wrt_scope: claims.wrt_scope ?? [],
      wrt_uid: claims.wrt_uid ?? '',
      token,
    };
  } catch {
    return null;
  }
}
