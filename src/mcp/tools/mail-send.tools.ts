import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { smtpService } from "../../services/smtp.service.js";
import { imapService } from "../../services/imap.service.js";

export function registerMailSendTools(server: McpServer) {
  // Tool 1: send_email
  server.tool(
    "send_email",
    "Belirtilen alıcı(lar)a yeni bir e-posta gönderir.",
    {
      to: z
        .union([z.string(), z.array(z.string())])
        .describe("Alıcı e-posta adresi veya adresler dizisi"),
      subject: z.string().describe("E-postanın konusu"),
      bodyText: z.string().describe("E-postanın düz metin (plain text) içeriği"),
      bodyHtml: z
        .string()
        .optional()
        .describe("İsteğe bağlı zengin HTML içeriği"),
      cc: z
        .union([z.string(), z.array(z.string())])
        .optional()
        .describe("Bilgi (CC) e-posta adresi veya adresleri"),
      bcc: z
        .union([z.string(), z.array(z.string())])
        .optional()
        .describe("Gizli bilgi (BCC) e-posta adresi veya adresleri"),
      replyTo: z
        .string()
        .optional()
        .describe("Yanıtların yönlendirileceği özel Reply-To adresi"),
    },
    async (options) => {
      try {
        const result = await smtpService.sendEmail(options);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "SENT",
                  message: "E-posta başarıyla gönderildi.",
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
              text: `[send_email Hatası] ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    }
  );

  // Tool 2: reply_email
  server.tool(
    "reply_email",
    "Gelen bir e-postaya RFC standartlarına uygun başlıklar (In-Reply-To, References, Re:) ve orijinal alıntıyla yanıt verir.",
    {
      originalUid: z
        .number()
        .describe("Yanıtlanacak orijinal e-postanın UID numarası"),
      folder: z
        .string()
        .optional()
        .describe("Orijinal e-postanın bulunduğu klasör (Varsayılan: 'INBOX')"),
      bodyText: z.string().describe("Yanıt olarak yazılacak mesajınız"),
      bodyHtml: z
        .string()
        .optional()
        .describe("İsteğe bağlı HTML formatlı yanıt mesajınız"),
      replyAll: z
        .boolean()
        .optional()
        .describe("Tüm alıcıları (CC listesini de) yanıta dahil etmek için true verin"),
    },
    async (options) => {
      try {
        const result = await smtpService.replyEmail(options);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "REPLIED",
                  message: "Yanıt başarıyla gönderildi ve orijinal e-posta ile ilişkilendirildi.",
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
              text: `[reply_email Hatası] ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    }
  );

  // Tool 3: verify_smtp_connection
  server.tool(
    "verify_smtp_connection",
    "SMTP sunucu yapılandırmasını ve bağlantısını test eder.",
    {},
    async () => {
      try {
        const ok = await smtpService.verifyConnection();
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ status: ok ? "CONNECTED" : "FAILED", message: "SMTP sunucusuna başarıyla bağlanıldı ve kimlik doğrulandı." }),
            },
          ],
        };
      } catch (error) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: `[verify_smtp_connection Hatası] ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    }
  );

  // Tool 4: create_draft
  server.tool(
    "create_draft",
    "E-postayı hemen göndermez; Taslaklar (Drafts) klasörüne yapay zeka tarafından oluşturulmuş bir taslak olarak kaydeder.",
    {
      to: z
        .union([z.string(), z.array(z.string())])
        .optional()
        .describe("Alıcı e-posta adresi veya adresleri"),
      subject: z.string().describe("Taslak e-postanın konusu"),
      bodyText: z.string().describe("Taslak düz metin (plain text) içeriği"),
      bodyHtml: z
        .string()
        .optional()
        .describe("İsteğe bağlı zengin HTML içeriği"),
      cc: z
        .union([z.string(), z.array(z.string())])
        .optional()
        .describe("Bilgi (CC) e-posta adresi veya adresleri"),
      bcc: z
        .union([z.string(), z.array(z.string())])
        .optional()
        .describe("Gizli bilgi (BCC) e-posta adresi veya adresleri"),
      replyTo: z
        .string()
        .optional()
        .describe("Özel Reply-To adresi"),
    },
    async (options) => {
      try {
        const result = await imapService.createDraft(options);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "DRAFT_CREATED",
                  message: `Taslak başarıyla "${result.folder}" klasörüne kaydedildi.`,
                  subject: options.subject,
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
              text: `[create_draft Hatası] ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    }
  );
}

