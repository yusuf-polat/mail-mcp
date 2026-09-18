import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { imapService } from "../../services/imap.service.js";

function generateIcs(params: {
  title: string;
  description: string;
  location?: string;
  startDate?: Date;
  endDate?: Date;
  organizer?: string;
  attendees?: string[];
}): string {
  const now = new Date();
  const formatUtc = (d: Date) =>
    d.toISOString().replace(/[-:]/g, "").split(".")[0] + "Z";

  const dtStamp = formatUtc(now);
  const start = params.startDate ? formatUtc(params.startDate) : formatUtc(new Date(now.getTime() + 3600000));
  const end = params.endDate
    ? formatUtc(params.endDate)
    : formatUtc(new Date(new Date(start).getTime() + 3600000));

  const uid = `event_${Date.now()}_${Math.random().toString(36).substring(2, 9)}@mail-mcp`;

  const lines = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//Mail MCP Server//Smart Calendar//TR",
    "CALSCALE:GREGORIAN",
    "METHOD:REQUEST",
    "BEGIN:VEVENT",
    `UID:${uid}`,
    `DTSTAMP:${dtStamp}`,
    `DTSTART:${start}`,
    `DTEND:${end}`,
    `SUMMARY:${params.title.replace(/\n/g, " ")}`,
    `DESCRIPTION:${params.description.replace(/\n/g, "\\n")}`,
  ];

  if (params.location) {
    lines.push(`LOCATION:${params.location.replace(/\n/g, " ")}`);
  }

  if (params.organizer) {
    lines.push(`ORGANIZER;CN=${params.organizer}:mailto:${params.organizer}`);
  }

  if (params.attendees && params.attendees.length > 0) {
    for (const att of params.attendees) {
      lines.push(`ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION:mailto:${att}`);
    }
  }

  lines.push("STATUS:CONFIRMED", "END:VEVENT", "END:VCALENDAR");

  return lines.join("\r\n");
}

export function registerMailCalendarTools(server: McpServer): void {
  server.tool(
    "extract_calendar_event",
    "E-postadaki toplantı, randevu ve etkinlik bilgilerini (tarih, saat, link, katılımcılar) çıkarır ve standart .ics (iCalendar) formatı üretir.",
    {
      uid: z.number().optional().describe("Toplantı bilgisi çıkarılacak e-postanın UID numarası"),
      subject: z.string().optional().describe("UID yoksa doğrudan konu başlığı"),
      bodyText: z.string().optional().describe("UID yoksa doğrudan e-posta gövdesi"),
      folder: z.string().optional().default("INBOX").describe("UID verildiğinde e-postanın klasörü"),
    },
    async ({ uid, subject, bodyText, folder }) => {
      try {
        let title = subject || "Toplantı / Etkinlik";
        let text = bodyText || "";
        let sender = "";
        const attendees: string[] = [];

        if (uid !== undefined) {
          const email = await imapService.readEmail(uid, folder, false);
          title = email.subject || title;
          text = email.text || "";
          if (email.from?.address) {
            sender = email.from.address;
            attendees.push(email.from.address);
          }
          if (email.to) {
            for (const t of email.to) {
              if (t.address && !attendees.includes(t.address)) attendees.push(t.address);
            }
          }
        }

        // Meeting URL detection
        const meetingRegex =
          /(https?:\/\/(?:[a-zA-Z0-9-]+\.)?(?:zoom\.us\/j\/[0-9]+|meet\.google\.com\/[a-z0-9-]+|teams\.microsoft\.com\/l\/meetup-join\/[^\s<>]+))/i;
        const meetingMatch = text.match(meetingRegex);
        const meetingUrl = meetingMatch ? meetingMatch[1] : undefined;

        // Date detection heuristics
        const dateRegex =
          /(\b\d{1,2}[./-]\d{1,2}[./-]\d{2,4}\b|\b\d{1,2}\s+(?:ocak|şubat|mart|nisan|mayıs|haziran|temmuz|ağustos|eylül|ekim|kasım|aralık|january|february|march|april|may|june|july|august|september|october|november|december)\s*\d{0,4})/i;
        const timeRegex = /(\b(?:[01]?\d|2[0-3]):[0-5]\d(?:\s*(?:am|pm))?\b)/i;

        const dateMatch = text.match(dateRegex);
        const timeMatch = text.match(timeRegex);

        const location = meetingUrl || "Online Toplantı";

        const icsContent = generateIcs({
          title,
          description: text.slice(0, 500),
          location,
          organizer: sender,
          attendees,
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  status: "SUCCESS",
                  event: {
                    title,
                    meetingUrl,
                    detectedDate: dateMatch ? dateMatch[1] : undefined,
                    detectedTime: timeMatch ? timeMatch[1] : undefined,
                    location,
                    attendees,
                  },
                  icsContent,
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
              text: `[extract_calendar_event Hatası] ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
        };
      }
    }
  );
}
