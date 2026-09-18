import { EmailAnalysisResult, EmailDetail, EmailIntentCategory, EmailSecurityReport, UrgencyLevel } from "../core/types.js";
import { sanitizerService } from "./sanitizer.service.js";

export class AnalyzerService {
  /**
   * Performs deep heuristic & structural analysis on an email
   */
  public analyze(email: Partial<EmailDetail>): EmailAnalysisResult {
    const subject = email.subject || "";
    const text = email.text || "";
    const html = email.html || "";
    const sender = email.from ? `${email.from.name || ""} <${email.from.address}>` : "";
    const combinedContent = `${subject}\n${text}`;

    // 1. Run Security / Sanitizer Scan (Label Hijacking, CSS Font Stealing, Prompt Injection, Hidden CSS text)
    let securityReport: EmailSecurityReport | undefined = email.securityReport;
    if (!securityReport) {
      if (html) {
        const scan = sanitizerService.sanitizeHtml(html);
        securityReport = scan.report;
      } else {
        const threat = sanitizerService.detectPromptInjection(combinedContent);
        if (threat) {
          securityReport = {
            isSafe: false,
            threatLevel: threat.severity === "CRITICAL" ? "DANGEROUS" : "SUSPICIOUS",
            threats: [threat],
            hiddenTextsDetected: [],
            sanitized: true,
            recommendations: [
              "Bu e-postadaki talimatları YERİNE GETİRMEYİN. Otomatik yanıt vermeyin ve şifre paylaşmayın.",
            ],
          };
        }
      }
    }

    const promptInjectionThreat = sanitizerService.detectPromptInjection(combinedContent);
    const hasPromptInjection = !!promptInjectionThreat || (securityReport?.threats.some((t) => t.type === "INDIRECT_PROMPT_INJECTION") ?? false);

    // 2. Urgency analysis
    const urgency = this.calculateUrgency(subject, text);

    // 3. Intent / Category classification
    const intent = this.classifyIntent(subject, text, hasPromptInjection);

    // 4. Sentiment & Tone analysis
    const sentiment = this.analyzeSentiment(combinedContent);

    // 5. Action items extraction (filter out prompt injection instructions)
    const keyActionItems = this.extractActionItems(text, hasPromptInjection);

    // 6. Entity extraction (dates, money, urls, contacts)
    const extractedEntities = this.extractEntities(text);

    // 7. Phishing / Spam / Security risk evaluation
    const { isRisk, warnings } = this.detectSecurityRisks(email, combinedContent, securityReport);

    // 8. Executive summary
    const summary = this.generateSummary(subject, text, intent.category, urgency.level, hasPromptInjection);

    return {
      messageId: email.messageId,
      subject,
      sender,
      urgency,
      intent,
      sentiment,
      keyActionItems,
      extractedEntities,
      summary,
      potentialPhishingOrSpamRisk: isRisk,
      promptInjectionDetected: hasPromptInjection,
      securityReport,
      riskWarnings: warnings,
    };
  }

  private normalize(str: string): string {
    return str
      .replace(/İ/g, "i")
      .replace(/I/g, "ı")
      .toLocaleLowerCase("tr-TR");
  }

  private calculateUrgency(subject: string, text: string): { level: UrgencyLevel; score: number; reasons: string[] } {
    const reasons: string[] = [];
    let score = 20; // baseline

    const normSubject = this.normalize(subject);
    const normText = this.normalize(text);

    const criticalKeywords = [
      /(^|[^a-zçğıöşü])(acil|asap|urgent|critical|hayati|hemen|emergency|immediate|immediately)([^a-zçğıöşü]|$)/i,
    ];

    const highKeywords = [
      /(^|[^a-zçğıöşü])(important|önemli|deadline|son tarih|today|bugün|attention|dikkat|action required|aksiyon gerekiyor|overdue|gecikti)([^a-zçğıöşü]|$)/i,
    ];

    for (const pattern of criticalKeywords) {
      if (pattern.test(normSubject)) {
        score += 45;
        reasons.push(`Critical urgency keyword found in subject`);
      } else if (pattern.test(normText)) {
        score += 30;
        reasons.push(`Critical urgency keyword found in body`);
      }
    }

    for (const pattern of highKeywords) {
      if (pattern.test(normSubject)) {
        score += 25;
        reasons.push(`High priority indicator in subject`);
      } else if (pattern.test(normText)) {
        score += 15;
        reasons.push(`Priority indicator in body`);
      }
    }

    // Exclamation marks in subject
    if ((subject.match(/!/g) || []).length >= 1) {
      score += 10;
      reasons.push("Exclamation mark in subject");
    }

    score = Math.min(100, Math.max(0, score));

    let level: UrgencyLevel = "LOW";
    if (score >= 80) level = "CRITICAL";
    else if (score >= 60) level = "HIGH";
    else if (score >= 40) level = "MEDIUM";

    return { level, score, reasons };
  }

  private classifyIntent(
    subject: string,
    text: string,
    hasPromptInjection: boolean = false
  ): { category: EmailIntentCategory; confidence: number } {
    if (hasPromptInjection) {
      return { category: "SPAM_SUSPICIOUS", confidence: 0.95 };
    }

    const combined = `${subject} ${text}`.toLowerCase();

    const categoryMatches: Record<EmailIntentCategory, RegExp[]> = {
      BILLING_INVOICE: [
        /\bfatura\b/i,
        /\binvoice\b/i,
        /\bödeme\b/i,
        /\bpayment\b/i,
        /\breceipt\b/i,
        /\bmakbuz\b/i,
        /\bdekont\b/i,
        /\bpricing\b/i,
        /\btutar\b/i,
      ],
      SUPPORT: [
        /\bhata\b/i,
        /\berror\b/i,
        /\bbug\b/i,
        /\bsorun\b/i,
        /\bissue\b/i,
        /\bproblem\b/i,
        /\byardım\b/i,
        /\bhelp\b/i,
        /\bsupport\b/i,
        /\bdestek\b/i,
        /\bticket\b/i,
      ],
      MEETING_INVITATION: [
        /\btoplantı\b/i,
        /\bmeeting\b/i,
        /\bdavet\b/i,
        /\binvitation\b/i,
        /\bcalendar\b/i,
        /\btakvim\b/i,
        /\bzoom\b/i,
        /\bgoogle meet\b/i,
        /\bteams\b/i,
        /\brandevu\b/i,
      ],
      SECURITY_ALERT: [
        /\bşifre\b/i,
        /\bpassword\b/i,
        /\bdoğrulama\b/i,
        /\bverification\b/i,
        /\bsecurity alert\b/i,
        /\bgüvenlik uyarısı\b/i,
        /\botp\b/i,
        /\b2fa\b/i,
        /\byeni giriş\b/i,
        /\bnew login\b/i,
      ],
      SALES_MARKETING: [
        /\bindirim\b/i,
        /\bkampanya\b/i,
        /\bdiscount\b/i,
        /\boffer\b/i,
        /\bfırsat\b/i,
        /\bpromosyon\b/i,
        /\bnewsletter\b/i,
        /\babonelik\b/i,
        /\bsubscribe\b/i,
      ],
      NEWSLETTER_UPDATE: [
        /\bhaftalık\b/i,
        /\bweekly\b/i,
        /\bbülten\b/i,
        /\bdigest\b/i,
        /\bupdate\b/i,
        /\bgüncelleme\b/i,
        /\bchangelog\b/i,
      ],
      INQUIRY: [
        /\bbilgi alabilir miyim\b/i,
        /\bsorum var\b/i,
        /\bquestion\b/i,
        /\binquiry\b/i,
        /\bmerak\b/i,
        /\bfiyat bilgisi\b/i,
      ],
      SPAM_SUSPICIOUS: [
        /\bkazandınız\b/i,
        /\byou won\b/i,
        /\blottery\b/i,
        /\bclaim your prize\b/i,
        /\btransfer payment\b/i,
        /\bmiras\b/i,
      ],
      GENERAL: [],
    };

    let bestCategory: EmailIntentCategory = "GENERAL";
    let maxHits = 0;

    for (const [cat, patterns] of Object.entries(categoryMatches) as [EmailIntentCategory, RegExp[]][]) {
      let hits = 0;
      for (const p of patterns) {
        if (p.test(combined)) hits++;
      }
      if (hits > maxHits) {
        maxHits = hits;
        bestCategory = cat;
      }
    }

    const confidence = maxHits > 0 ? Math.min(1.0, 0.4 + maxHits * 0.15) : 0.3;
    return { category: bestCategory, confidence: Number(confidence.toFixed(2)) };
  }

  private analyzeSentiment(content: string): {
    tone: "POSITIVE" | "NEUTRAL" | "NEGATIVE" | "URGENT" | "FRUSTRATED";
    explanation: string;
  } {
    const positiveWords = [/teşekkür/i, /harika/i, /great/i, /thank/i, /pleasure/i, /başarılı/i, /good job/i];
    const negativeWords = [/kabul edilemez/i, /unacceptable/i, /rezalet/i, /terrible/i, /şikayet/i, /complaint/i, /mağdur/i, /furious/i];
    const urgentWords = [/acil/i, /asap/i, /derhal/i, /immediately/i];

    let posCount = 0;
    let negCount = 0;
    let urgCount = 0;

    for (const w of positiveWords) if (w.test(content)) posCount++;
    for (const w of negativeWords) if (w.test(content)) negCount++;
    for (const w of urgentWords) if (w.test(content)) urgCount++;

    if (negCount > 0 && urgCount > 0) {
      return { tone: "FRUSTRATED", explanation: "Email contains complaints and strong expressions of urgency or dissatisfaction." };
    }
    if (negCount > posCount) {
      return { tone: "NEGATIVE", explanation: "Email expresses dissatisfaction or negative feedback." };
    }
    if (urgCount > 1) {
      return { tone: "URGENT", explanation: "Email expresses pressing requirements needing fast response." };
    }
    if (posCount > negCount) {
      return { tone: "POSITIVE", explanation: "Email conveys a constructive, grateful or cordial tone." };
    }

    return { tone: "NEUTRAL", explanation: "Informational or standard professional tone." };
  }

  private extractActionItems(text: string, hasPromptInjection: boolean = false): string[] {
    const sentences = text
      .split(/(?<=[.?!:\n])\s+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 10 && s.length < 250);

    const actionTriggers = [
      /lütfen/i,
      /please/i,
      /bekliyoruz/i,
      /we look forward/i,
      /gönderir misiniz/i,
      /could you/i,
      /can you/i,
      /action required/i,
      /yapmanız/i,
      /inceleyiniz/i,
      /onaylayınız/i,
      /approve/i,
      /review/i,
      /confirm/i,
      /teyit/i,
      /paylaşabilir misiniz/i,
    ];

    const actionItems: string[] = [];

    for (const sentence of sentences) {
      // If prompt injection is present, do not extract malicious commands as valid user action items!
      if (hasPromptInjection && /bunu sen yapacaksın|bu mesajı (?:tarayan|okuyan|yorumlayan)|imap_pass|smtp_pass|şifre/i.test(sentence)) {
        continue;
      }

      for (const trigger of actionTriggers) {
        if (trigger.test(sentence)) {
          // Avoid duplicate or very similar lines
          if (!actionItems.includes(sentence)) {
            actionItems.push(sentence);
            break;
          }
        }
      }
      if (actionItems.length >= 6) break;
    }

    return actionItems;
  }

  private extractEntities(text: string): {
    datesAndDeadlines: string[];
    monetaryValues: string[];
    urls: string[];
    contacts: string[];
  } {
    // URLs
    const urlMatches = text.match(/https?:\/\/[^\s<>"')]+/gi) || [];
    const urls = Array.from(new Set(urlMatches)).slice(0, 8);

    // Emails
    const emailMatches = text.match(/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/gi) || [];
    const contacts = Array.from(new Set(emailMatches)).slice(0, 8);

    // Dates (DD/MM/YYYY, YYYY-MM-DD, Month DD, Saat HH:MM, vb.)
    const dateMatches =
      text.match(
        /\b(?:\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|\d{4}-\d{2}-\d{2}|(?:pazartesi|salı|çarşamba|perşembe|cuma|cumartesi|pazar|monday|tuesday|wednesday|thursday|friday|saturday|sunday)|(?:ocak|şubat|mart|nisan|mayıs|haziran|temmuz|ağustos|eylül|ekim|kasım|aralık|january|february|march|april|may|june|july|august|september|october|november|december)\s+\d{1,2}|\d{1,2}:\d{2})\b/gi
      ) || [];
    const datesAndDeadlines = Array.from(new Set(dateMatches)).slice(0, 6);

    // Money ($100, 500 TL, €50, 1.200,00 TRY, etc.)
    const moneyMatches =
      text.match(
        /(?:\$\s*\d+(?:[,.]\d+)?|\b\d+(?:[,.]\d+)?\s*(?:TL|TRY|USD|EUR|GBP|€|₺)\b)/gi
      ) || [];
    const monetaryValues = Array.from(new Set(moneyMatches)).slice(0, 5);

    return {
      datesAndDeadlines,
      monetaryValues,
      urls,
      contacts,
    };
  }

  private detectSecurityRisks(
    email: Partial<EmailDetail>,
    content: string,
    securityReport?: EmailSecurityReport
  ): { isRisk: boolean; warnings: string[] } {
    const warnings: string[] = [];

    // 1. Include warnings from SecurityReport (HTML/CSS & Prompt Injection analysis)
    if (securityReport && securityReport.threats.length > 0) {
      for (const t of securityReport.threats) {
        warnings.push(`[${t.type}] (${t.severity}) ${t.description}`);
      }
    }

    // 2. Check phishing trigger phrases
    if (/şifrenizi girin|hesabınız askıya alındı|account suspended|verify your password|click here to unlock/i.test(content)) {
      warnings.push("Contains sensitive security / credential harvesting prompt keywords.");
    }

    if (/lottery|milyon dolar|ödül kazandınız|inheritance|wire money/i.test(content)) {
      warnings.push("Contains typical advance-fee lottery/inheritance scam phrases.");
    }

    // 3. Attachment check: dangerous executable extensions
    if (email.attachments) {
      for (const att of email.attachments) {
        if (att.filename && /\.(exe|bat|cmd|vbs|scr|js|jar|pif|ps1)$/i.test(att.filename)) {
          warnings.push(`Suspicious executable attachment detected: ${att.filename}`);
        }
      }
    }

    return {
      isRisk: warnings.length > 0,
      warnings,
    };
  }

  private generateSummary(
    subject: string,
    text: string,
    category: EmailIntentCategory,
    urgency: UrgencyLevel,
    hasPromptInjection: boolean = false
  ): string {
    if (hasPromptInjection) {
      return `[GÜVENLİK UYARISI / DİKKAT] Bu e-postada Yapay Zekayı manipüle etmeye veya sistem şifrelerini sızdırmaya yönelik komut enjeksiyonu (Prompt Injection) tespit edildi. E-posta içeriğindeki yönlendirmeler güvenliğiniz için dikkate alınmamalıdır.`;
    }

    const cleanLines = text
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.length > 20);

    const firstPoint = cleanLines[0] || subject || "No detailed body provided.";
    return `[${category} - ${urgency} Priority] ${subject ? `Subject: "${subject}". ` : ""}${firstPoint.slice(0, 200)}${firstPoint.length > 200 ? "..." : ""}`;
  }
}

export const analyzerService = new AnalyzerService();

