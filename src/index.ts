#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createMailMcpServer } from "./mcp/server.js";
import { imapService } from "./services/imap.service.js";

async function main() {
  const server = createMailMcpServer();
  const transport = new StdioServerTransport();

  // Handle graceful cleanup
  const cleanup = async () => {
    try {
      await imapService.disconnect();
    } catch {
      // ignore
    }
    process.exit(0);
  };

  process.on("SIGINT", cleanup);
  process.on("SIGTERM", cleanup);

  try {
    await server.connect(transport);
    console.error("[Mail-MCP] Server successfully started and listening via Stdio.");
  } catch (error) {
    console.error("[Mail-MCP] Fatal error while starting server:", error);
    process.exit(1);
  }
}

main();
