import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AttestClient } from '@attest-dev/sdk';
import { errorResult } from '../error.js';

export function registerApprovalTools(server: McpServer, client: AttestClient): void {
  server.tool(
    'request_approval',
    'Create a pending approval request for a high-risk delegation. Use this after issuing or delegating a credential when a human must approve extra scope before work continues. Requires a valid parent token and returns a challenge object that can later be inspected with get_approval or resolved with grant_approval or deny_approval.',
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
    'Fetch the current status for one approval challenge by challenge_id. Use this after request_approval when you need a one-time status check for whether the request is still pending, approved, or rejected; it does not perform repeated polling by itself. Returns the approval record from Attest, and invalid or unknown challenge IDs will surface as an MCP error response.',
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
    'Approve a pending approval challenge and mint the HITL-authorized child credential. Use this only when a human approver has already authenticated and you have their OIDC identity token; for status checks use get_approval instead. This changes system state, consumes the pending approval, and returns the delegated token that should be used for the gated step.',
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
    'Reject a pending approval challenge without minting a child credential. Use this when a human declines the requested access; for passive inspection use get_approval instead. This changes the approval status in Attest and returns the final rejected state for that challenge.',
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
