#!/usr/bin/env node

/**
 * @attest-dev/mcp-server — MCP server exposing Attest credential management,
 * audit, and approval tools.
 *
 * Agents running in Claude Desktop, Cursor, Windsurf, or any MCP host can
 * call these tools to issue credentials, delegate to sub-agents, revoke
 * access, query audit trails, and manage approvals.
 *
 * Environment variables:
 *   ATTEST_API_KEY   (required) — org API key
 *   ATTEST_BASE_URL  (optional) — defaults to https://api.attestdev.com
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { AttestClient } from '@attest-dev/sdk';
import { registerCredentialTools } from './tools/credentials.js';
import { registerTaskTools } from './tools/tasks.js';
import { registerReportingTools } from './tools/reporting.js';
import { registerApprovalTools } from './tools/approvals.js';

const apiKey = process.env['ATTEST_API_KEY'];
if (!apiKey) {
  console.error('[attest-mcp-server] ATTEST_API_KEY environment variable is required');
  process.exit(1);
}

const baseUrl = process.env['ATTEST_BASE_URL'] ?? 'https://api.attestdev.com';

const client = new AttestClient({ baseUrl, apiKey });

const server = new McpServer({
  name: 'attest',
  version: '0.1.0',
});

registerCredentialTools(server, client, baseUrl);
registerTaskTools(server, client);
registerReportingTools(server, client);
registerApprovalTools(server, client);

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`[attest-mcp-server] Running on stdio (${baseUrl})`);
}

main().catch((err) => {
  console.error('[attest-mcp-server] Fatal:', err);
  process.exit(1);
});
