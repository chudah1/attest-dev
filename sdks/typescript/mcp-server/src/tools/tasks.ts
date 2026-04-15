import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AttestClient } from '@attest-dev/sdk';
import { errorResult } from '../error.js';

export function registerTaskTools(server: McpServer, client: AttestClient): void {
  server.tool(
    'list_tasks',
    'List recent Attest task trees for the authenticated organization, optionally filtered by user, agent, status, or limit. Use this to recover recent workflows when you do not already know the task ID; use get_audit_trail or get_evidence once you have a specific task_id. This is a read operation that returns task summaries only and does not mutate task state.',
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
    'Fetch the full audit event chain for a single task tree. Use this when you already know the task_id and need detailed chronology for issuance, delegation, actions, lifecycle events, approvals, or revocations; use list_tasks first if you need to discover candidate tasks. Returns the raw Attest audit events for that task and does not change state.',
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
    'Fetch the signed evidence packet for one task tree. Use this when you need a portable proof artifact for compliance review, incident analysis, or independent verification; use get_audit_trail for a simpler raw event timeline. Returns the full evidence packet produced by Attest and does not mutate any task state.',
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
