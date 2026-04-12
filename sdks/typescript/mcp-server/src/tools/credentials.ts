import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AttestClient } from '@attest-dev/sdk';
import { errorResult } from '../error.js';

export function registerCredentialTools(server: McpServer, client: AttestClient, baseUrl: string): void {
  server.tool(
    'issue_credential',
    'Issue a scoped credential for an agent',
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
    'Narrow a parent credential for a child agent',
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
    'Revoke a credential and cascade to all descendants',
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
    'Check if a token is valid (signature, expiry, structure)',
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
    'Check if a credential JTI has been revoked',
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
