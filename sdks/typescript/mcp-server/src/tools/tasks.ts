import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AttestClient } from '@attest-dev/sdk';
import { errorResult } from '../error.js';

export function registerTaskTools(server: McpServer, client: AttestClient): void {
  server.tool(
    'list_tasks',
    'List task trees with optional filters',
    {
      user_id: z.string().optional().describe('Filter by user ID'),
      agent_id: z.string().optional().describe('Filter by agent ID'),
      status: z.enum(['active', 'revoked']).optional().describe('Filter by status'),
      limit: z.number().int().positive().optional().describe('Max results'),
    },
    async (args) => {
      try {
        const params: Parameters<typeof client.listTasks>[0] = {};
        if (args.user_id !== undefined) params.userId = args.user_id;
        if (args.agent_id !== undefined) params.agentId = args.agent_id;
        if (args.status !== undefined) params.status = args.status;
        if (args.limit !== undefined) params.limit = args.limit;
        const result = await client.listTasks(params);
        return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.tool(
    'get_audit_trail',
    'Get the full event chain for a task',
    {
      task_id: z.string().describe('Task tree ID'),
    },
    async (args) => {
      try {
        const result = await client.audit(args.task_id);
        return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.tool(
    'get_evidence',
    'Get a signed evidence packet for compliance and verification',
    {
      task_id: z.string().describe('Task tree ID'),
    },
    async (args) => {
      try {
        const result = await client.fetchEvidence(args.task_id);
        return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
      } catch (err) {
        return errorResult(err);
      }
    },
  );
}
