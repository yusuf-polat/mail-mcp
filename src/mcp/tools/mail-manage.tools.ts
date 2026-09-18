import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { imapService } from "../../services/imap.service.js";

export function registerMailManageTools(server: McpServer): void {
  // 1. List Folders
  server.tool(
    "list_folders",
    "Posta kutusundaki tüm klasörleri, etiketleri ve özel kullanım yollarını listeler.",
    {},
    async () => {
      try {
        const folders = await imapService.listFolders();
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  count: folders.length,
                  folders,
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
              text: `[list_folders Hatası] ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    }
  );

  // 2. Move Email
  server.tool(
    "move_email",
    "Belirtilen e-postayı (UID) hedef klasöre veya etikete taşır.",
    {
      uid: z.number().describe("Taşınacak e-postanın UID numarası"),
      destinationFolder: z
        .string()
        .describe("Hedef klasör adı (örn: '[Gmail]/Trash', '[Gmail]/Spam', 'Arşiv', vb.)"),
      sourceFolder: z
        .string()
        .optional()
        .default("INBOX")
        .describe("E-postanın bulunduğu kaynak klasör (Varsayılan: 'INBOX')"),
    },
    async ({ uid, destinationFolder, sourceFolder }) => {
      try {
        const result = await imapService.moveEmail(uid, destinationFolder, sourceFolder);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "MOVED",
                  message: `E-posta başarıyla "${destinationFolder}" klasörüne taşındı.`,
                  uid,
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
              text: `[move_email Hatası] ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    }
  );

  // 3. Flag Email
  server.tool(
    "flag_email",
    "E-postaya bayrak ekler, kaldırır veya günceller (örn: yıldızlama '\\\\Flagged', okundu '\\\\Seen').",
    {
      uid: z.number().describe("İşlem yapılacak e-postanın UID numarası"),
      flags: z
        .array(z.string())
        .describe("Uygulanacak bayraklar dizisi (örn: ['\\\\Flagged'], ['\\\\Seen'], vb.)"),
      action: z
        .enum(["add", "remove", "set"])
        .optional()
        .default("add")
        .describe("İşlem türü: 'add' (ekle), 'remove' (kaldır), 'set' (tümünü ayarla). Varsayılan: 'add'"),
      folder: z
        .string()
        .optional()
        .default("INBOX")
        .describe("E-postanın bulunduğu klasör (Varsayılan: 'INBOX')"),
    },
    async ({ uid, flags, action, folder }) => {
      try {
        const result = await imapService.flagEmail(uid, flags, action, folder);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "FLAGGED",
                  message: `Bayrak işlemi başarıyla uygulandı (${action}: ${flags.join(", ")}).`,
                  uid,
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
              text: `[flag_email Hatası] ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    }
  );

  // 4. Delete Email
  server.tool(
    "delete_email",
    "E-postayı çöp kutusuna taşır veya kalıcı olarak siler.",
    {
      uid: z.number().describe("Silinecek e-postanın UID numarası"),
      permanent: z
        .boolean()
        .optional()
        .default(false)
        .describe("Kalıcı olarak silinsin mi? (true ise geri dönüşsüz silinir, false ise Çöp Kutusuna taşınır. Varsayılan: false)"),
      folder: z
        .string()
        .optional()
        .default("INBOX")
        .describe("E-postanın bulunduğu klasör (Varsayılan: 'INBOX')"),
    },
    async ({ uid, permanent, folder }) => {
      try {
        const result = await imapService.deleteEmail(uid, permanent, folder);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "DELETED",
                  message: permanent
                    ? "E-posta kalıcı olarak silindi."
                    : "E-posta başarıyla Çöp Kutusuna (Trash) taşındı.",
                  uid,
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
              text: `[delete_email Hatası] ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    }
  );

  // 5. Check for Updates
  server.tool(
    "check_for_updates",
    "Mail-MCP sunucusunun GitHub'daki en güncel sürüm ve güvenlik yamalarıyla uyumlu olup olmadığını denetler.",
    {
      autoUpdate: z
        .boolean()
        .optional()
        .default(false)
        .describe("Eğer yeni bir güncelleme varsa otomatik git pull ile güncellensin mi? (Varsayılan: false)"),
    },
    async ({ autoUpdate }) => {
      try {
        const { updaterService } = await import("../../services/updater.service.js");
        const status = await updaterService.checkVersion(autoUpdate);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(status, null, 2),
            },
          ],
        };
      } catch (error) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: `[check_for_updates Hatası] ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    }
  );
}
