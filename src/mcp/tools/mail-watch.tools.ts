import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { imapService } from "../../services/imap.service.js";

export function registerMailWatchTools(server: McpServer) {
  server.tool(
    "watch_new_emails",
    "IMAP IDLE protokolünü kullanarak gelen kutusunu anlık olarak dinler. Yeni bir e-posta düştüğü anda veya zaman aşımı süresi dolduğunda sonucu döner.",
    {
      folder: z
        .string()
        .optional()
        .describe("Dinlenecek klasör (Varsayılan: 'INBOX')"),
      timeoutSeconds: z
        .number()
        .optional()
        .describe(
          "Yeni e-posta beklenirken beklenecek maksimum saniye (10-300 sn, varsayılan: 30 sn). Yeni mail gelirse anında döner."
        ),
    },
    async ({ folder, timeoutSeconds }) => {
      try {
        const result = await imapService.watchNewEmails({
          folder,
          timeoutSeconds,
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: result.newEmailsCount > 0 ? "NEW_EMAILS_ARRIVED" : "IDLE_TIMEOUT_NO_NEW_MAIL",
                  ...result,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: `[watch_new_emails Hatası] ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    }
  );
}
