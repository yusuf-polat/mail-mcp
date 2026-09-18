import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { imapService } from "../../services/imap.service.js";

export function registerMailAttachmentTools(server: McpServer): void {
  server.tool(
    "download_attachment",
    "Belirtilen e-postadaki eki indirir. GÜVENLİK ZORUNLULUĞU: Dosya kesinlikle indirilmeden önce Windows Defender ve çok katmanlı sezgisel virüs taramasından geçirilir. Tehdit bulunursa dosya derhal imha edilir ve indirme iptal edilir.",
    {
      uid: z.number().describe("E-postanın UID numarası"),
      attachmentIdentifier: z
        .union([z.string(), z.number()])
        .describe("Dosya adı (örn: 'fatura.pdf') veya ekin sırası (0, 1, 2 vb.)"),
      targetDir: z
        .string()
        .optional()
        .default("./downloads")
        .describe("Ekin kaydedileceği yerel dizin (Varsayılan: './downloads')"),
      folder: z
        .string()
        .optional()
        .default("INBOX")
        .describe("E-postanın bulunduğu klasör (Varsayılan: 'INBOX')"),
    },
    async ({ uid, attachmentIdentifier, targetDir, folder }) => {
      try {
        const result = await imapService.downloadAttachment(
          uid,
          attachmentIdentifier,
          targetDir,
          folder
        );
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "VERIFIED_AND_DOWNLOADED",
                  message: `✓ Dosya virüs taramasından başarıyla geçti (TEMİZ) ve güvenle kaydedildi: ${result.filename}`,
                  savedPath: result.savedPath,
                  size: result.size,
                  contentType: result.contentType,
                  antivirusScan: result.antivirusScan,
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
              text: `[download_attachment Hatası] ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    }
  );
}
