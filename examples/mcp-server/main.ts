/**
 * MCP tool server protected by Attest credentials.
 *
 * Every tool call requires a valid Attest JWT with the right scope.
 * The `withAttest` wrapper handles verification, scope checks, and
 * revocation checks automatically — zero auth code in tool handlers.
 *
 * Requirements:
 *   npm install @attest-dev/sdk @attest-dev/mcp @modelcontextprotocol/sdk zod tsx
 *
 * Run:
 *   npx tsx main.ts
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { withAttest, getAttestContext } from "@attest-dev/mcp";
import { z } from "zod";

// -- Create and protect the server ------------------------------------------

const server = new McpServer({
  name: "acme-tools",
  version: "1.0.0",
});

const protectedServer = withAttest(server, {
  issuerUri: process.env.ATTEST_BASE_URL || "https://api.attestdev.com",

  // Log violations (blocked tool calls) for monitoring
  onViolation: (event) => {
    console.error(
      `[attest] BLOCKED ${event.toolName}: ${event.reason}`,
      event.jti ? `jti=${event.jti}` : "",
    );
  },

  // Optional: explicit scope mapping for non-standard tool names
  toolScopeMap: {
    send_email: "gmail:send",
    search_contacts: "contacts:read",
  },
});

// -- Register tools ---------------------------------------------------------
// These handlers only execute if the caller holds a valid credential
// with the required scope. No auth code needed inside the handler.

protectedServer.tool(
  "send_email",
  "Send an email to a recipient",
  {
    to: z.string().describe("Recipient email address"),
    subject: z.string().describe("Email subject"),
    body: z.string().describe("Email body"),
  },
  async (args, extra) => {
    // Access the verified credential claims inside the handler
    const ctx = getAttestContext(extra);
    console.error(
      `[send_email] Acting on behalf of ${ctx?.att_uid}, task ${ctx?.att_tid}`,
    );

    // Your actual email logic here
    return {
      content: [
        {
          type: "text" as const,
          text: `Email sent to ${args.to}: "${args.subject}"`,
        },
      ],
    };
  },
);

protectedServer.tool(
  "search_contacts",
  "Search the contact directory",
  {
    query: z.string().describe("Search query"),
  },
  async (args, extra) => {
    const ctx = getAttestContext(extra);
    console.error(
      `[search_contacts] Query="${args.query}" by ${ctx?.att_uid}`,
    );

    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify([
            { name: "Alice Smith", email: "alice@example.com" },
            { name: "Bob Jones", email: "bob@example.com" },
          ]),
        },
      ],
    };
  },
);

// -- Start server -----------------------------------------------------------

async function main() {
  const transport = new StdioServerTransport();
  await protectedServer.connect(transport);
  console.error("[acme-tools] MCP server running on stdio (Attest-protected)");
}

main().catch(console.error);
