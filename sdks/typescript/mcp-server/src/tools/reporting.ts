import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AttestClient } from '@attest-dev/sdk';
import { errorResult } from '../error.js';

export function registerReportingTools(server: McpServer, client: AttestClient): void {
  server.tool(
    'report_action',
    'Append a tool execution outcome to the Attest audit log for the credential in use. Use this after a meaningful business action such as sending email, updating billing, or calling an internal API; it records side effects rather than authorizing them. Returns a small confirmation object, and callers should use report_status for lifecycle transitions like started or completed.',
    {
      token: z.string().describe('Credential JWT'),
      tool: z.string().describe('Tool name that was executed'),
      outcome: z.enum(['success', 'failure', 'error', 'skipped']).describe('Execution outcome'),
      meta: z.record(z.string()).optional().describe('Additional key-value metadata'),
    },
    async (args) => {
      try {
        const params: Parameters<typeof client.reportAction>[0] = {
          token: args.token,
          tool: args.tool,
          outcome: args.outcome,
        };
        if (args.meta !== undefined) params.meta = args.meta;
        await client.reportAction(params);
        return { content: [{ type: 'text' as const, text: JSON.stringify({ reported: true, tool: args.tool, outcome: args.outcome }) }] };
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.tool(
    'report_status',
    'Append an agent lifecycle event such as started, completed, or failed to the Attest audit log. Use this to mark step boundaries or overall task progress; use report_action for concrete tool outcomes instead. Returns a confirmation object and does not mint, verify, or revoke credentials.',
    {
      token: z.string().describe('Credential JWT'),
      status: z.enum(['started', 'completed', 'failed']).describe('Agent lifecycle status'),
      meta: z.record(z.string()).optional().describe('Additional key-value metadata'),
    },
    async (args) => {
      try {
        const params: Parameters<typeof client.reportStatus>[0] = {
          token: args.token,
          status: args.status,
        };
        if (args.meta !== undefined) params.meta = args.meta;
        await client.reportStatus(params);
        return { content: [{ type: 'text' as const, text: JSON.stringify({ reported: true, status: args.status }) }] };
      } catch (err) {
        return errorResult(err);
      }
    },
  );
}
