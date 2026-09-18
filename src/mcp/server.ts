import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerMailReadTools } from "./tools/mail-read.tools.js";
import { registerMailSendTools } from "./tools/mail-send.tools.js";
import { registerMailWatchTools } from "./tools/mail-watch.tools.js";
import { registerMailAnalyzeTools } from "./tools/mail-analyze.tools.js";
import { registerMailManageTools } from "./tools/mail-manage.tools.js";
import { registerMailAttachmentTools } from "./tools/mail-attachment.tools.js";
import { registerMailCalendarTools } from "./tools/mail-calendar.tools.js";

export function createMailMcpServer(): McpServer {
  const server = new McpServer({
    name: "mail-mcp-server",
    version: "1.0.0",
  });

  // Register all tool modules
  registerMailReadTools(server);
  registerMailSendTools(server);
  registerMailWatchTools(server);
  registerMailAnalyzeTools(server);
  registerMailManageTools(server);
  registerMailAttachmentTools(server);
  registerMailCalendarTools(server);

  return server;
}

