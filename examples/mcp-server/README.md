# MCP Server + Attest

An MCP tool server where every tool call requires a valid Attest credential.

## Setup

```bash
npm install @attest-dev/sdk @attest-dev/mcp @modelcontextprotocol/sdk zod
```

## Run

```bash
npx tsx main.ts
```

## What it demonstrates

- **`withAttest(server, opts)`** — two-line integration that wraps every `server.tool()` with credential enforcement
- **`getAttestContext(extra)`** — read verified claims inside tool handlers
- **`toolScopeMap`** — explicit scope mapping for non-standard tool names
- **`onViolation`** — callback for monitoring blocked tool calls
- **Automatic scope derivation** — `send_email` → `email:send`, `search_contacts` → `contacts:read`
