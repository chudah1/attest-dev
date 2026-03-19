/**
 * @warrant/mcp — Warrant credential enforcement middleware for MCP servers.
 *
 * Drop-in wrapper for any McpServer that checks every tool call against a
 * Warrant credential before letting it through.
 *
 * Quick start:
 *
 *   import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
 *   import { createWarrantMcpServer } from '@warrant/mcp';
 *
 *   const server = new McpServer({ name: 'my-server', version: '1.0.0' });
 *   // ...register tools normally...
 *
 *   const secured = createWarrantMcpServer(server, {
 *     warrantBaseUrl: 'http://localhost:8080',
 *     extractToken: (req) => req.params._meta?.warrant_token ?? null,
 *   });
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import type {
  CallToolRequest,
  CallToolResult,
} from '@modelcontextprotocol/sdk/types.js';
import type { JWKSResponse, WarrantClaims } from '@warrant/sdk';
import { WarrantVerifier } from './middleware.js';

export type { DeniedReason, DeniedCode, VerifyOptions } from './middleware.js';
export { WarrantVerifier, isScopeCovered } from './middleware.js';

// ── Public types ──────────────────────────────────────────────────────────────

export interface DeniedReason {
  code: 'missing_token' | 'invalid_token' | 'expired' | 'revoked' | 'scope_violation';
  tool: string;
  jti?: string;
  message: string;
}

export interface WarrantMcpOptions {
  /** Base URL of the Warrant server, e.g. "http://localhost:8080". */
  warrantBaseUrl: string;
  /**
   * Full JWKS endpoint URL.
   * Defaults to `warrantBaseUrl + "/.well-known/jwks.json"`.
   */
  jwksUrl?: string;
  /**
   * Pre-loaded JWKS for offline/test mode.
   * When set, the JWKS endpoint is never contacted.
   */
  staticJwks?: JWKSResponse;
  /**
   * Extract the Warrant token from an incoming tool-call request.
   *
   * Default strategy (in order):
   *  1. `request.params._meta?.warrant_token`
   *  2. `request.params.arguments?.warrant_token`
   *
   * Supply your own function to read from a different location (e.g. a
   * shared HTTP header captured by your transport layer).
   */
  extractToken?: (request: CallToolRequest) => string | null;
  /**
   * Whether to check the Warrant server's revocation list.
   * Default: true.
   * Set to false for latency-sensitive or fully offline scenarios.
   */
  checkRevocation?: boolean;
  /**
   * Milliseconds before the revocation HTTP call times out.
   * On timeout the call is denied (fail-closed). Default: 500.
   */
  revocationTimeoutMs?: number;
  /**
   * Scope prefix for tool name mapping.
   * Tool "send_email" → required scope "<prefix>:send_email".
   * Default: "tool".
   */
  scopePrefix?: string;
  /**
   * Optional audit hook — called whenever a tool call is denied, before the
   * error response is sent. Useful for logging / alerting.
   */
  onDenied?: (reason: DeniedReason, request: CallToolRequest) => void;
}

// ── Default token extractor ───────────────────────────────────────────────────

/**
 * Default token extraction strategy:
 *  1. `request.params._meta?.warrant_token`  (MCP meta field)
 *  2. `request.params.arguments?.warrant_token`  (tool argument)
 */
export function defaultExtractToken(request: CallToolRequest): string | null {
  // _meta is typed as Record<string, unknown> | undefined in MCP SDK
  const meta = request.params._meta as Record<string, unknown> | undefined;
  if (typeof meta?.['warrant_token'] === 'string') {
    return meta['warrant_token'];
  }

  const args = request.params.arguments as Record<string, unknown> | undefined;
  if (typeof args?.['warrant_token'] === 'string') {
    return args['warrant_token'];
  }

  return null;
}

/**
 * Utility for transports that capture the HTTP Authorization header separately
 * and inject it into tool calls.
 *
 * @example
 *   extractToken: () => extractTokenFromHeader(req.headers.authorization ?? '')
 */
export function extractTokenFromHeader(authHeader: string): string | null {
  const trimmed = authHeader.trim();
  if (!trimmed.toLowerCase().startsWith('bearer ')) return null;
  const token = trimmed.slice(7).trim();
  return token.length > 0 ? token : null;
}

// ── Denied response builder ───────────────────────────────────────────────────

function deniedResult(
  reason: DeniedReason,
  grantedScope?: string[],
  prefix?: string,
): CallToolResult {
  const body: Record<string, unknown> = {
    error: 'warrant_denied',
    code: reason.code,
    tool: reason.tool,
    message: reason.message,
  };

  if (reason.code === 'scope_violation') {
    body['required_scope'] = `${prefix ?? 'tool'}:${reason.tool}`;
    if (grantedScope !== undefined) body['granted_scope'] = grantedScope;
  }

  if (reason.jti !== undefined) {
    body['jti'] = reason.jti;
  }

  return {
    isError: true,
    content: [
      {
        type: 'text',
        text: JSON.stringify(body, null, 2),
      },
    ],
  };
}

// ── createWarrantMcpServer ────────────────────────────────────────────────────

/**
 * Wrap an existing McpServer so that every tool call is checked against a
 * Warrant credential before reaching the original handler.
 *
 * The returned server is the same McpServer instance — its
 * `CallToolRequestSchema` handler is replaced with one that performs
 * credential verification first, then delegates to the original handler on
 * success.
 *
 * @param server   An already-configured McpServer (tools may already be registered).
 * @param options  Warrant enforcement configuration.
 * @returns        The same McpServer instance, now with enforcement active.
 */
export function createWarrantMcpServer(
  server: McpServer,
  options: WarrantMcpOptions,
): McpServer {
  const verifier = new WarrantVerifier({
    warrantBaseUrl: options.warrantBaseUrl,
    jwksUrl: options.jwksUrl,
    staticJwks: options.staticJwks,
    checkRevocation: options.checkRevocation,
    revocationTimeoutMs: options.revocationTimeoutMs,
    scopePrefix: options.scopePrefix,
  });

  const extractToken = options.extractToken ?? defaultExtractToken;
  const scopePrefix = options.scopePrefix ?? 'tool';

  // Intercept the tool-call handler at the MCP Server level.
  // setRequestHandler replaces any previously registered handler for this
  // schema, so we capture the original first via the server's internal
  // _requestHandlers map, then install our enforcement wrapper.
  //
  // McpServer stores handlers on `server.server` (the underlying Server
  // instance). We access the internal _requestHandlers map to preserve the
  // original handler so we can delegate to it after verification.
  //
  // If McpServer has not registered a handler yet (empty server), the wrapper
  // installs one that returns a "tool not found" error — matching default MCP
  // behaviour.

  // Access the underlying low-level Server instance.
  const rawServer = (server as unknown as { server: RawMcpServer }).server;

  // Capture the original handler (may be undefined if tools aren't registered yet).
  const originalHandler = rawServer._requestHandlers.get(
    CallToolRequestSchema.shape.method.value,
  ) as ToolHandler | undefined;

  // Install the enforcement wrapper.
  rawServer.setRequestHandler(
    CallToolRequestSchema,
    async (request: CallToolRequest): Promise<CallToolResult> => {
      const toolName = request.params.name;

      // ── 1. Extract token ──────────────────────────────────────────────────
      const token = extractToken(request);
      if (!token) {
        const reason: DeniedReason = {
          code: 'missing_token',
          tool: toolName,
          message: 'No Warrant token found in request',
        };
        options.onDenied?.(reason, request);
        return deniedResult(reason, undefined, scopePrefix);
      }

      // ── 2. Verify ─────────────────────────────────────────────────────────
      const result = await verifier.verify(token, toolName);

      if (!result.allowed) {
        const reason = result.reason as DeniedReason;
        const grantedScope =
          reason.code === 'scope_violation'
            ? tryDecodeScope(token)
            : undefined;
        options.onDenied?.(reason, request);
        return deniedResult(reason, grantedScope, scopePrefix);
      }

      // ── 3. Delegate to original handler ───────────────────────────────────
      if (!originalHandler) {
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                error: 'tool_not_found',
                tool: toolName,
                message: `No handler registered for tool "${toolName}"`,
              }),
            },
          ],
        };
      }

      return originalHandler(request) as Promise<CallToolResult>;
    },
  );

  return server;
}

// ── WarrantToolMiddleware ─────────────────────────────────────────────────────

/**
 * Lower-level API for wrapping individual tool handlers rather than an entire
 * McpServer. Useful when you only want to protect specific tools, or when
 * integrating with a custom server setup.
 *
 * @example
 *   const middleware = new WarrantToolMiddleware({
 *     warrantBaseUrl: 'http://localhost:8080',
 *   });
 *
 *   server.tool('send_email', schema, middleware.wrap('send_email', sendEmailHandler));
 */
export class WarrantToolMiddleware {
  private readonly verifier: WarrantVerifier;
  private readonly extractToken: (request: CallToolRequest) => string | null;
  private readonly scopePrefix: string;
  private readonly onDenied?: (
    reason: DeniedReason,
    request: CallToolRequest,
  ) => void;

  constructor(options: WarrantMcpOptions) {
    this.verifier = new WarrantVerifier({
      warrantBaseUrl: options.warrantBaseUrl,
      jwksUrl: options.jwksUrl,
      staticJwks: options.staticJwks,
      checkRevocation: options.checkRevocation,
      revocationTimeoutMs: options.revocationTimeoutMs,
      scopePrefix: options.scopePrefix,
    });
    this.extractToken = options.extractToken ?? defaultExtractToken;
    this.scopePrefix = options.scopePrefix ?? 'tool';
    this.onDenied = options.onDenied;
  }

  /**
   * Wrap a tool handler with Warrant enforcement.
   *
   * @param toolName  The name of the tool (used for scope mapping).
   * @param handler   The original async handler to delegate to on success.
   */
  wrap<TArgs extends Record<string, unknown>>(
    toolName: string,
    handler: (args: TArgs, claims: WarrantClaims) => Promise<CallToolResult>,
  ): (request: CallToolRequest) => Promise<CallToolResult> {
    return async (request: CallToolRequest): Promise<CallToolResult> => {
      const token = this.extractToken(request);
      if (!token) {
        const reason: DeniedReason = {
          code: 'missing_token',
          tool: toolName,
          message: 'No Warrant token found in request',
        };
        this.onDenied?.(reason, request);
        return deniedResult(reason, undefined, this.scopePrefix);
      }

      const result = await this.verifier.verify(token, toolName);

      if (!result.allowed) {
        const reason = result.reason as DeniedReason;
        const grantedScope =
          reason.code === 'scope_violation'
            ? tryDecodeScope(token)
            : undefined;
        this.onDenied?.(reason, request);
        return deniedResult(reason, grantedScope, this.scopePrefix);
      }

      const args = (request.params.arguments ?? {}) as TArgs;
      return handler(args, result.claims);
    };
  }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/**
 * Best-effort decode of wrt_scope from a JWT without verifying the signature.
 * Used only to populate the "granted_scope" field in scope violation errors.
 */
function tryDecodeScope(token: string): string[] | undefined {
  try {
    const parts = token.split('.');
    if (parts.length < 2 || !parts[1]) return undefined;
    const payload = JSON.parse(
      Buffer.from(parts[1], 'base64url').toString('utf8'),
    ) as Record<string, unknown>;
    const scope = payload['wrt_scope'];
    if (Array.isArray(scope) && scope.every((s) => typeof s === 'string')) {
      return scope as string[];
    }
    return undefined;
  } catch {
    return undefined;
  }
}

// ── Internal MCP SDK type shims ───────────────────────────────────────────────
//
// The MCP SDK doesn't export the internal _requestHandlers map in its public
// types. We define minimal shims here to avoid `any` in the implementation.

type ToolHandler = (request: CallToolRequest) => unknown;

interface RawMcpServer {
  _requestHandlers: Map<string, ToolHandler>;
  setRequestHandler<T extends { method: string }>(
    schema: { shape: { method: { value: string } } },
    handler: (request: T) => unknown,
  ): void;
}
