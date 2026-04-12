import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AttestClient } from '@attest-dev/sdk';
import { errorResult } from '../error.js';

export function registerReportingTools(server: McpServer, client: AttestClient): void {
  server.tool(
    'report_action',
    'Log a tool execution outcome',
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
    'Log an agent lifecycle event',
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
