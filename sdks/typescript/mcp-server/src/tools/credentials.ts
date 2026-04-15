import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AttestClient } from '@attest-dev/sdk';
import { errorResult } from '../error.js';

export function registerCredentialTools(server: McpServer, client: AttestClient, baseUrl: string): void {
  server.tool(
    'issue_credential',
    'Issue a new root credential for a task. Use this at the start of a workflow when an orchestrator or top-level agent needs explicit scoped authority tied to a human user and instruction. Returns a signed JWT plus claims including the task tree ID; use delegate_credential for child agents instead of issuing multiple unrelated root credentials.',
    {
      agent_id: z.string().describe('Agent identifier'),
      user_id: z.string().describe('Human principal who authorized the task'),
      scope: z.array(z.string()).describe('Permission scopes, e.g. ["email:send"]'),
      instruction: z.string().describe('Task instruction'),
      ttl_seconds: z.number().optional().describe('Token lifetime in seconds (default 3600, max 86400)'),
    },
    async (args) => {
      try {
        const params: Parameters<typeof client.issue>[0] = {
          agent_id: args.agent_id,
          user_id: args.user_id,
          scope: args.scope,
          instruction: args.instruction,
        };
        if (args.ttl_seconds !== undefined) params.ttl_seconds = args.ttl_seconds;
        const result = await client.issue(params);
        return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.tool(
    'delegate_credential',
    'Create a narrower child credential from an existing parent credential. Use this when handing work to a sub-agent or isolated step that should receive only a subset of the parent scope. The server enforces that child_scope is a subset of the parent; if you need the original root authority, use issue_credential instead.',
    {
      parent_token: z.string().describe('Parent JWT credential'),
      child_agent: z.string().describe('Child agent identifier'),
      child_scope: z.array(z.string()).describe('Narrowed scopes (must be subset of parent)'),
      ttl_seconds: z.number().optional().describe('Child token lifetime in seconds'),
    },
    async (args) => {
      try {
        const params: Parameters<typeof client.delegate>[0] = {
          parent_token: args.parent_token,
          child_agent: args.child_agent,
          child_scope: args.child_scope,
        };
        if (args.ttl_seconds !== undefined) params.ttl_seconds = args.ttl_seconds;
        const result = await client.delegate(params);
        return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.tool(
    'revoke_credential',
    'Revoke one credential and cascade that revocation through all of its descendants in the same task tree. Use this when a workflow should be stopped or contained; this is a state-changing operation, not a dry run. Returns a confirmation object, and later checks should use check_revocation or list_tasks rather than calling revoke_credential again.',
    {
      jti: z.string().describe('Credential unique ID'),
      revoked_by: z.string().optional().describe('Who initiated revocation'),
    },
    async (args) => {
      try {
        await client.revoke(args.jti, args.revoked_by);
        return { content: [{ type: 'text' as const, text: JSON.stringify({ revoked: true, jti: args.jti }) }] };
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.tool(
    'verify_credential',
    'Perform an offline-style validity check for one credential using the org JWKS fetched from Attest. Use this to inspect a token before acting on it or when debugging why a credential was rejected; for revocation-only checks use check_revocation instead. Requires the org_id that issued the token and returns validity, decoded claims, and warning details.',
    {
      token: z.string().describe('JWT credential to verify'),
      org_id: z.string().describe('Organization ID (needed to fetch JWKS)'),
    },
    async (args) => {
      try {
        const jwks = await client.fetchJWKS(args.org_id);
        const result = await client.verify(args.token, jwks);
        return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.tool(
    'check_revocation',
    'Check whether a specific credential JTI is currently revoked. Use this for a one-time revocation lookup when you already know the credential ID; it does not verify signature, expiry, or task history. Returns a small revocation status object, and network or API failures are returned as MCP errors.',
    {
      jti: z.string().describe('Credential unique ID'),
    },
    async (args) => {
      try {
        const res = await fetch(
          `${baseUrl}/v1/revoked/${encodeURIComponent(args.jti)}`,
          { signal: AbortSignal.timeout(10_000) },
        );
        if (!res.ok) {
          return errorResult(new Error(`Revocation check failed (HTTP ${res.status})`));
        }
        const data = await res.json() as { revoked: boolean };
        return { content: [{ type: 'text' as const, text: JSON.stringify(data) }] };
      } catch (err) {
        return errorResult(err);
      }
    },
  );
}
