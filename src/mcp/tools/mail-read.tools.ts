import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { imapService } from "../../services/imap.service.js";

export function registerMailReadTools(server: McpServer) {
  // Tool 1: check_inbox
  server.tool(
    "check_inbox",
    "Gelen kutusundaki (veya belirtilen klasördeki) en son e-postaları özet bilgilerle listeler.",
    {
      folder: z
        .string()
        .optional()
        .describe("Kontrol edilecek posta klasörü (Varsayılan: 'INBOX')"),
      limit: z
        .number()
        .optional()
        .describe("Getirilecek maksimum e-posta sayısı (1-100, varsayılan: 20)"),
      unreadOnly: z
        .boolean()
        .optional()
        .describe("Yalnızca okunmamış e-postaları listelemek için true verin"),
    },
    async ({ folder, limit, unreadOnly }) => {
      try {
        const emails = await imapService.checkInbox({ folder, limit, unreadOnly });
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  folder: folder || "INBOX",
                  totalRetrieved: emails.length,
                  unreadOnly: !!unreadOnly,
                  emails,
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
              text: `[check_inbox Hatası] ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    }
  );

  // Tool 2: search_emails
  server.tool(
    "search_emails",
    "Gelişmiş arama kriterleri ile e-postaları arar (gönderen, konu, gövde, tarih, okunmamışlık vb.).",
    {
      query: z
        .string()
        .optional()
        .describe("Konu veya gövdede serbest metin araması"),
      folder: z
        .string()
        .optional()
        .describe("Aranacak klasör (Varsayılan: 'INBOX')"),
      from: z.string().optional().describe("Gönderen adres veya isim filtresi"),
      to: z.string().optional().describe("Alıcı adres filtresi"),
      subject: z.string().optional().describe("Konu içinde geçen kelime filtresi"),
      since: z
        .string()
        .optional()
        .describe("Bu tarihten sonraki mailler (Örn: '2025-01-01')"),
      before: z
        .string()
        .optional()
        .describe("Bu tarihten önceki mailler (Örn: '2025-12-31')"),
      unreadOnly: z
        .boolean()
        .optional()
        .describe("Sadece okunmamış mailleri getirmek için true"),
      limit: z
        .number()
        .optional()
        .describe("Maksimum sonuç sayısı (1-100, varsayılan: 25)"),
    },
    async (criteria) => {
      try {
        const emails = await imapService.searchEmails(criteria);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  criteria,
                  totalFound: emails.length,
                  emails,
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
              text: `[search_emails Hatası] ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    }
  );

  // Tool 3: read_email
  server.tool(
    "read_email",
    "UID numarası verilen belirli bir e-postayı gövdesi, ek bilgileri ve başlıklarıyla eksiksiz okur.",
    {
      uid: z.number().describe("Okunacak e-postanın UID numarası"),
      folder: z
        .string()
        .optional()
        .describe("E-postanın bulunduğu klasör (Varsayılan: 'INBOX')"),
      markAsSeen: z
        .boolean()
        .optional()
        .describe("E-posta okundu olarak işaretlensin mi? (Varsayılan: true)"),
    },
    async ({ uid, folder, markAsSeen }) => {
      try {
        const email = await imapService.readEmail(uid, folder || "INBOX", markAsSeen !== false);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(email, null, 2),
            },
          ],
        };
      } catch (error) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: `[read_email Hatası] ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    }
  );
}
