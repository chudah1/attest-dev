import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AttestClient } from '@attest-dev/sdk';
import { errorResult } from '../error.js';

export function registerApprovalTools(server: McpServer, client: AttestClient): void {
  server.tool(
    'request_approval',
    'Ask a human to approve a delegation',
    {
      parent_token: z.string().describe('Parent credential JWT'),
      agent_id: z.string().describe('Requesting agent identifier'),
      att_tid: z.string().describe('Task tree ID'),
      intent: z.string().describe('Human-readable reason for the request'),
      requested_scope: z.array(z.string()).describe('Desired permission scopes'),
    },
    async (args) => {
      try {
        const result = await client.requestApproval({
          parent_token: args.parent_token,
          agent_id: args.agent_id,
          att_tid: args.att_tid,
          intent: args.intent,
          requested_scope: args.requested_scope,
        });
        return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.tool(
    'get_approval',
    'Poll approval status',
    {
      challenge_id: z.string().describe('Approval challenge ID'),
    },
    async (args) => {
      try {
        const result = await client.getApproval(args.challenge_id);
        return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.tool(
    'grant_approval',
    'Grant an approval request with an OIDC identity token',
    {
      challenge_id: z.string().describe('Approval challenge ID'),
      id_token: z.string().describe('OIDC identity token from the approver'),
    },
    async (args) => {
      try {
        const result = await client.grantApproval(args.challenge_id, args.id_token);
        return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.tool(
    'deny_approval',
    'Deny an approval request',
    {
      challenge_id: z.string().describe('Approval challenge ID'),
    },
    async (args) => {
      try {
        const result = await client.denyApproval(args.challenge_id);
        return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
      } catch (err) {
        return errorResult(err);
      }
    },
  );

}
