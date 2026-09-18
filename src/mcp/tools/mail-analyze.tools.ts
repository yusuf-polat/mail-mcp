import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { analyzerService } from "../../services/analyzer.service.js";
import { imapService } from "../../services/imap.service.js";
import { EmailDetail } from "../../core/types.js";

export function registerMailAnalyzeTools(server: McpServer) {
  server.tool(
    "analyze_email",
    "Bir e-postanın içeriğini derinlemesine analiz eder: aciliyet derecesi, niyet/kategori, ton/duygu, aksiyon maddeleri, tarihler, para tutarları, özet ve phishing/spam riskleri.",
    {
      uid: z
        .number()
        .optional()
        .describe("Posta kutusundaki bir e-postayı doğrudan UID ile okuyup analiz etmek için UID numarası"),
      folder: z
        .string()
        .optional()
        .describe("UID verildiğinde e-postanın bulunduğu klasör (Varsayılan: 'INBOX')"),
      subject: z
        .string()
        .optional()
        .describe("UID verilmediğinde doğrudan analiz edilecek konu başlığı"),
      bodyText: z
        .string()
        .optional()
        .describe("UID verilmediğinde doğrudan analiz edilecek e-posta gövdesi"),
    },
    async ({ uid, folder, subject, bodyText }) => {
      try {
        let emailToAnalyze: Partial<EmailDetail>;

        if (uid !== undefined) {
          const fetched = await imapService.readEmail(uid, folder || "INBOX", false);
          emailToAnalyze = fetched;
        } else if (subject !== undefined || bodyText !== undefined) {
          emailToAnalyze = {
            subject: subject || "",
            text: bodyText || "",
            attachments: [],
          };
        } else {
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: "Lütfen analiz için geçerli bir 'uid' belirtin veya 'subject' / 'bodyText' girin.",
              },
            ],
          };
        }

        const analysis = analyzerService.analyze(emailToAnalyze);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(analysis, null, 2),
            },
          ],
        };
      } catch (error) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: `[analyze_email Hatası] ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    }
  );

  // Tool 2: find_unsubscribe_links
  server.tool(
    "find_unsubscribe_links",
    "Bülten ve tanıtım e-postalarındaki abonelikten çıkma (List-Unsubscribe başlıkları veya gövdedeki iptal bağlantıları) yollarını tespit eder.",
    {
      uid: z.number().describe("Abonelikten çıkma bağlantısı taranacak e-postanın UID numarası"),
      folder: z.string().optional().default("INBOX").describe("E-postanın bulunduğu klasör (Varsayılan: 'INBOX')"),
    },
    async ({ uid, folder }) => {
      try {
        const email = await imapService.readEmail(uid, folder, false);
        const headers = email.headers || {};

        let listUnsubHeader: string | undefined;
        for (const [key, val] of Object.entries(headers)) {
          if (key.toLowerCase() === "list-unsubscribe") {
            listUnsubHeader = Array.isArray(val) ? val.join(", ") : String(val);
            break;
          }
        }

        let oneClickUrl: string | undefined;
        let mailtoAddress: string | undefined;

        if (listUnsubHeader) {
          const urlMatch = listUnsubHeader.match(/<(https?:\/\/[^>]+)>/i);
          if (urlMatch) oneClickUrl = urlMatch[1];

          const mailtoMatch = listUnsubHeader.match(/<(mailto:[^>]+)>/i);
          if (mailtoMatch) mailtoAddress = mailtoMatch[1];
        }

        const bodyLinks: string[] = [];
        const combinedText = `${email.text || ""} ${email.html || ""}`;
        const unsubRegex =
          /(https?:\/\/[^\s"'<>]*(?:unsubscribe|optout|opt-out|abone|subscription)[^\s"'<>]*)/gi;

        let match: RegExpExecArray | null;
        while ((match = unsubRegex.exec(combinedText)) !== null) {
          const link = match[1].replace(/[.,;:)]+$/, "");
          if (!bodyLinks.includes(link) && link !== oneClickUrl) {
            bodyLinks.push(link);
          }
          if (bodyLinks.length >= 5) break;
        }

        const hasUnsubscribe = !!(listUnsubHeader || oneClickUrl || mailtoAddress || bodyLinks.length > 0);

        let instructions = "Bu e-postada herhangi bir abonelik iptali bağlantısı tespit edilemedi.";
        if (oneClickUrl) {
          instructions = `Tek tıkla abonelik iptali bağlantısı: ${oneClickUrl}`;
        } else if (bodyLinks.length > 0) {
          instructions = `E-posta gövdesindeki iptal bağlantısını ziyaret edin: ${bodyLinks[0]}`;
        } else if (mailtoAddress) {
          instructions = `Şu adrese e-posta göndererek abonelikten çıkabilirsiniz: ${mailtoAddress}`;
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  uid,
                  subject: email.subject,
                  from: email.from,
                  hasUnsubscribe,
                  listUnsubscribeHeader: listUnsubHeader,
                  oneClickUrl,
                  mailtoAddress,
                  bodyLinks,
                  instructions,
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
              text: `[find_unsubscribe_links Hatası] ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    }
  );

  // Tool 3: triage_inbox
  server.tool(
    "triage_inbox",
    "Gelen kutusundaki son e-postaları topluca tarar, önem derecesine göre gruplar (Güvenlik, Finans, Acil Görevler, Bültenler) ve eyleme dönüştürülebilir özet rapor sunar.",
    {
      limit: z
        .number()
        .optional()
        .default(15)
        .describe("İncelenecek maksimum e-posta sayısı (Varsayılan: 15)"),
      folder: z
        .string()
        .optional()
        .default("INBOX")
        .describe("Taranacak klasör (Varsayılan: 'INBOX')"),
    },
    async ({ limit, folder }) => {
      try {
        const summaries = await imapService.checkInbox({ folder, limit });
        const criticalAndUrgent: any[] = [];
        const financialAndInvoices: any[] = [];
        const securityAlerts: any[] = [];
        const newslettersAndMarketing: any[] = [];
        const keyActionItems: any[] = [];

        for (const item of summaries) {
          try {
            const full = await imapService.readEmail(item.uid, folder, false);
            const a = analyzerService.analyze(full);

            const senderStr = item.from ? `${item.from.name || ""} <${item.from.address}>` : "Bilinmiyor";

            // Categorize
            if (a.urgency.level === "CRITICAL" || a.urgency.level === "HIGH" || a.urgency.score >= 55) {
              criticalAndUrgent.push({
                uid: item.uid,
                subject: item.subject,
                from: senderStr,
                urgencyScore: a.urgency.score,
                reasons: a.urgency.reasons,
              });
            }

            if (a.intent.category === "BILLING_INVOICE" || a.extractedEntities.monetaryValues.length > 0) {
              financialAndInvoices.push({
                uid: item.uid,
                subject: item.subject,
                from: senderStr,
                money: a.extractedEntities.monetaryValues,
                date: item.date,
              });
            }

            if (a.intent.category === "SECURITY_ALERT" || a.potentialPhishingOrSpamRisk || /güvenlik|security|şifre|password|verify/i.test(item.subject || "")) {
              securityAlerts.push({
                uid: item.uid,
                subject: item.subject,
                from: senderStr,
                date: item.date,
              });
            }

            if (a.intent.category === "NEWSLETTER_UPDATE" || a.intent.category === "SALES_MARKETING") {
              newslettersAndMarketing.push({
                uid: item.uid,
                subject: item.subject,
                from: senderStr,
              });
            }

            if (a.keyActionItems.length > 0) {
              for (const act of a.keyActionItems.slice(0, 2)) {
                keyActionItems.push({
                  uid: item.uid,
                  subject: item.subject,
                  action: act,
                });
              }
            }
          } catch {
            // Ignore single read failure and continue
          }
        }

        const executiveSummary = [
          `Posta kutusundaki son ${summaries.length} e-posta incelendi.`,
          criticalAndUrgent.length > 0
            ? `🚨 ${criticalAndUrgent.length} adet yüksek aciliyetli e-posta var.`
            : "✓ Acil aksiyon gerektiren kritik bir e-posta yok.",
          financialAndInvoices.length > 0
            ? `💳 ${financialAndInvoices.length} adet fatura/finansal işlem tespit edildi.`
            : "",
          securityAlerts.length > 0
            ? `🛡️ ${securityAlerts.length} adet güvenlik/hesap bildirimi mevcut.`
            : "",
          newslettersAndMarketing.length > 0
            ? `📰 ${newslettersAndMarketing.length} adet bülten/tanıtım postası bulundu.`
            : "",
        ]
          .filter(Boolean)
          .join(" ");

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  scannedCount: summaries.length,
                  timestamp: new Date().toISOString(),
                  executiveSummary,
                  criticalAndUrgent,
                  financialAndInvoices,
                  securityAlerts,
                  newslettersAndMarketing,
                  keyActionItems,
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
              text: `[triage_inbox Hatası] ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    }
  );
}

