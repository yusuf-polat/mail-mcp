import { EmailSecurityReport, SecurityThreatItem } from "../core/types.js";
import { getEnv } from "../config/env.js";

export class SanitizerService {
  /**
   * Comprehensive scan and sanitization of HTML email content.
   * Defends against PortSwigger / Gareth Heyes attacks:
   * 1. Label Hijacking (for attribute abuse)
   * 2. CSS Font/OTP Exfiltration (@font-face, unicode-range, descent-override, @keyframes)
   * 3. IP Exfiltration & Tracking (image-set, var(), @import, remote stylesheets, 1x1 tracking pixels)
   * 4. CSS Steganography & Hidden AI Prompts (opacity:0, font-size:0, display:none, ::before/::after content)
   * 5. Malicious scripts, iframes, and dangerous handlers
   */
  public sanitizeHtml(
    html: string,
    options: { blockRemoteContent?: boolean } = {}
  ): {
    sanitizedHtml: string;
    threats: SecurityThreatItem[];
    hiddenTexts: string[];
    report: EmailSecurityReport;
  } {
    if (!html || typeof html !== "string") {
      return {
        sanitizedHtml: "",
        threats: [],
        hiddenTexts: [],
        report: {
          isSafe: true,
          threatLevel: "SAFE",
          threats: [],
          hiddenTextsDetected: [],
          sanitized: true,
          recommendations: [],
        },
      };
    }

    const threats: SecurityThreatItem[] = [];
    const hiddenTexts: string[] = [];
    let clean = html;

    // 1. Detect & Strip Script / Iframe / Dangerous Tags
    if (/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi.test(clean)) {
      threats.push({
        type: "MALICIOUS_TAG_OR_SCRIPT",
        severity: "CRITICAL",
        description: "Zararlı <script> JavaScript etiketi tespit edildi ve temizlendi.",
      });
      clean = clean.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "");
    }

    if (/<(iframe|object|embed|applet)\b[^>]*>/gi.test(clean)) {
      threats.push({
        type: "MALICIOUS_TAG_OR_SCRIPT",
        severity: "CRITICAL",
        description: "Güvensiz gömülü nesne (<iframe/object/embed>) tespit edildi ve kaldırıldı.",
      });
      clean = clean.replace(/<\/?(iframe|object|embed|applet)\b[^>]*>/gi, "");
    }

    // Strip inline javascript: and event handlers (onload, onclick, onmouseover, etc.)
    if (/on\w+\s*=\s*["'][^"']*["']/gi.test(clean) || /href\s*=\s*["']\s*javascript:/gi.test(clean)) {
      threats.push({
        type: "MALICIOUS_TAG_OR_SCRIPT",
        severity: "CRITICAL",
        description: "Inline JavaScript olay dinleyicisi veya javascript: URI tespit edildi ve engellendi.",
      });
      clean = clean.replace(/\s+on\w+\s*=\s*(?:'[^']*'|"[^"]*"|[^\s>]+)/gi, "");
      clean = clean.replace(/href\s*=\s*(?:'javascript:[^']*'|"javascript:[^"]*")/gi, 'href="#"');
    }

    // 2. Detect & Neutralize Label Hijacking
    // Matches <label ... for="target_id" ...>
    const labelForMatches = clean.match(/<label\b[^>]*\bfor\s*=\s*['"]?([^'">\s]+)['"]?[^>]*>/gi);
    if (labelForMatches && labelForMatches.length > 0) {
      threats.push({
        type: "LABEL_HIJACKING",
        severity: "HIGH",
        description:
          "Label Hijacking (Etiket Kaçırma) zafiyeti tespit edildi! <label for='...'> etiketi e-posta istemcisi arayüz butonlarını tetikleyememesi için etkisiz hale getirildi.",
        snippet: labelForMatches.slice(0, 3).join(" | "),
      });
      // Strip 'for' attribute from label tags
      clean = clean.replace(/(<label\b[^>]*?)\s*\bfor\s*=\s*(?:'[^']*'|"[^"]*"|[^\s>]+)/gi, "$1 data-safe-for=\"neutered\"");
    }

    // 3. Detect & Neutralize CSS Font/OTP Keylogging & Exfiltration
    // Checks @font-face, unicode-range, descent-override, size-adjust, @keyframes loops
    const fontFacePattern = /@font-face\s*\{[^}]*\}/gi;
    const fontFaceMatches = clean.match(fontFacePattern);
    const unicodeRangeMatches = clean.match(/unicode-range\s*:[^;}]*/gi);
    const descentOverrideMatches = clean.match(/descent-override\s*:[^;}]*/gi);
    const keyframesMatches = clean.match(/@keyframes\s+[^{]+\{[^}]*\{[^}]*\}[^}]*\}/gi);

    if (fontFaceMatches || unicodeRangeMatches || descentOverrideMatches || keyframesMatches) {
      threats.push({
        type: "CSS_DATA_EXFILTRATION",
        severity: "CRITICAL",
        description:
          "CSS Font/OTP Sızdırma saldırısı tespit edildi! (@font-face, unicode-range, descent-override veya @keyframes kullanılarak token/karakter çalma girişimi). Zararlı CSS kuralları temizlendi.",
        snippet: (fontFaceMatches || keyframesMatches || []).slice(0, 2).join(" | "),
      });
      clean = clean.replace(fontFacePattern, "/* [BLOCKED_FONT_EXFILTRATION] */");
      clean = clean.replace(/@keyframes\s+[^{]+\{[^}]*\{[^}]*\}[^}]*\}/gi, "/* [BLOCKED_KEYFRAMES] */");
      clean = clean.replace(/descent-override\s*:[^;}]*/gi, "");
      clean = clean.replace(/size-adjust\s*:[^;}]*/gi, "");
      clean = clean.replace(/unicode-range\s*:[^;}]*/gi, "");
    }

    // 4. Detect & Neutralize Remote Tracking & IP Leaks (image-set, var(), @import, remote stylesheets)
    const imageSetMatches = clean.match(/image-set\s*\([^)]*\)/gi);
    const importMatches = clean.match(/@import\s+(?:url\([^)]+\)|['"][^'"]+['"])/gi);
    const linkStyleMatches = clean.match(/<link\b[^>]*\brel\s*=\s*['"]?stylesheet['"]?[^>]*>/gi);

    if (imageSetMatches || importMatches || linkStyleMatches) {
      threats.push({
        type: "REMOTE_TRACKING_OR_IP_LEAK",
        severity: "HIGH",
        description:
          "IP ve Tarayıcı Bilgisi Sızdırma (image-set, @import veya harici CSS bağlantısı) tespit edildi. Gmail proxy atlatma mekanizmaları temizlendi.",
        snippet: (imageSetMatches || importMatches || linkStyleMatches || []).slice(0, 2).join(" | "),
      });
      clean = clean.replace(/image-set\s*\([^)]*\)/gi, "none");
      clean = clean.replace(/@import\s+(?:url\([^)]+\)|['"][^'"]+['"]);?/gi, "/* [BLOCKED_IMPORT] */");
      clean = clean.replace(/<link\b[^>]*\brel\s*=\s*['"]?stylesheet['"]?[^>]*>/gi, "");
    }

    // Block remote background-images if option enabled or tracking pixel detected
    if (options.blockRemoteContent) {
      clean = clean.replace(/background(-image)?\s*:\s*url\s*\([^)]*\)/gi, "background-image: none");
      clean = clean.replace(/<img\b[^>]*\bsrc\s*=\s*['"]https?:\/\/[^'"]+['"][^>]*>/gi, (match) => {
        return match.replace(/\bsrc\s*=\s*['"][^'"]+['"]/i, 'src="data:image/svg+xml;utf8,<svg xmlns=\'http://www.w3.org/2000/svg\' width=\'20\' height=\'20\'><text y=\'15\' fill=\'gray\'>[Image Blocked]</text></svg>"');
      });
    }

    // 5. Detect & Neutralize CSS Steganography / Hidden AI Prompts
    // Finds elements hidden via CSS with text content: opacity:0, font-size:0, display:none, left:-9999px, etc.
    const hiddenElementRegex = /<([a-z0-9]+)\b[^>]*style\s*=\s*["'][^"']*(?:opacity\s*:\s*0(?:\.0+)?|font-size\s*:\s*0(?:px|pt|em|rem)?|display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*transparent|left\s*:\s*-[0-9]{3,}px)[^"']*["'][^>]*>(.*?)<\/\1>/gis;

    let hiddenMatch: RegExpExecArray | null;
    while ((hiddenMatch = hiddenElementRegex.exec(html)) !== null) {
      const rawText = hiddenMatch[2].replace(/<[^>]+>/g, "").trim();
      if (rawText.length > 0) {
        hiddenTexts.push(rawText);
      }
    }

    // CSS Pseudo-element content extraction (e.g. ::before { content: "secret command" })
    const pseudoContentRegex = /::(?:before|after)\s*\{[^}]*content\s*:\s*["']([^"']+)["'][^}]*\}/gi;
    let pseudoMatch: RegExpExecArray | null;
    while ((pseudoMatch = pseudoContentRegex.exec(clean)) !== null) {
      const contentText = pseudoMatch[1].trim();
      if (contentText.length > 0 && contentText !== " " && contentText !== "") {
        hiddenTexts.push(`[CSS ::pseudo-content] ${contentText}`);
      }
    }

    if (hiddenTexts.length > 0) {
      threats.push({
        type: "HIDDEN_CSS_STEGANOGRAPHY",
        severity: "HIGH",
        description:
          "CSS Steganografi / Gizli Metin Tuzağı tespit edildi! Ekranda kullanıcıdan gizlenen ancak Yapay Zekayı manipüle etmeye yönelik DOM metinleri izole edildi.",
        snippet: hiddenTexts.slice(0, 3).join(" | "),
      });
      // Neutralize hidden stealth styles to make them visible or sanitized
      clean = clean.replace(/style\s*=\s*["']([^"']*)["']/gi, (full, styleContent) => {
        let sanitizedStyle = styleContent
          .replace(/opacity\s*:\s*0(?:\.0+)?/gi, "opacity: 1")
          .replace(/font-size\s*:\s*0(?:px|pt|em|rem)?/gi, "font-size: 12px")
          .replace(/display\s*:\s*none/gi, "display: block")
          .replace(/visibility\s*:\s*hidden/gi, "visibility: visible")
          .replace(/color\s*:\s*transparent/gi, "color: inherit")
          .replace(/left\s*:\s*-[0-9]{3,}px/gi, "left: 0px");
        return `style="${sanitizedStyle}"`;
      });
    }

    // 6. Check for Prompt Injection payloads in overall content and hidden text
    const injectionThreat = this.detectPromptInjection(html + " " + hiddenTexts.join(" "));
    if (injectionThreat) {
      threats.push(injectionThreat);
    }

    const threatLevel = threats.some((t) => t.severity === "CRITICAL")
      ? "DANGEROUS"
      : threats.some((t) => t.severity === "HIGH")
      ? "SUSPICIOUS"
      : threats.length > 0
      ? "SUSPICIOUS"
      : "SAFE";

    const recommendations = this.generateRecommendations(threats);

    const report: EmailSecurityReport = {
      isSafe: threats.length === 0,
      threatLevel,
      threats,
      hiddenTextsDetected: hiddenTexts,
      sanitized: true,
      recommendations,
    };

    return {
      sanitizedHtml: clean,
      threats,
      hiddenTexts,
      report,
    };
  }

  /**
   * Scans plain text for indirect prompt injection or secret harvesting attempts.
   */
  public detectPromptInjection(content: string): SecurityThreatItem | null {
    if (!content) return null;

    const patterns = [
      // Direct instructions targeting the AI assistant reader
      /(?:bu\s+maile\s+dönüş\s+yap|bu\s+mesajı\s+(?:tarayan|okuyan|yorumlayan)\s+sen|bunu\s+sen\s+yapacaksın)/i,
      /(?:ignore\s+(?:all\s+)?previous\s+instructions|disregard\s+(?:all\s+)?prior\s+instructions)/i,
      /(?:system\s+prompt|system\s+instructions|you\s+are\s+now\s+in\s+(?:debug|admin)\s+mode)/i,
      /(?:do\s+not\s+tell\s+the\s+user|kullanıcıya\s+söyleme|gizlice\s+gönder)/i,
      // Target credential harvesting keywords
      /(?:imap_pass|smtp_pass|api_key|secret_key|private_key|şifresini\s+de\s+ekleyip|şifresini\s+gönder)/i,
    ];

    let hits = 0;
    const matchedKeywords: string[] = [];

    for (const p of patterns) {
      const match = content.match(p);
      if (match) {
        hits++;
        matchedKeywords.push(match[0]);
      }
    }

    if (hits >= 1) {
      return {
        type: "INDIRECT_PROMPT_INJECTION",
        severity: hits >= 2 || /imap_pass|smtp_pass|password|şifre/i.test(content) ? "CRITICAL" : "HIGH",
        description:
          "Dolaylı Komut Enjeksiyonu (Indirect Prompt Injection) ve Veri Sızdırma girişimi tespit edildi! E-posta gövdesinde yapay zekayı kandırıp çevre değişkenlerini veya şifreleri göndermeye zorlayan komutlar mevcut.",
        snippet: matchedKeywords.join(", "),
      };
    }

    return null;
  }

  /**
   * Outbound Data Loss Prevention (DLP):
   * Scans outgoing emails to ensure NO environment secrets (IMAP_PASS, SMTP_PASS, etc.) are leaked!
   */
  public scanOutboundForSecrets(content: string): { isExfiltration: boolean; matchedSecretName?: string } {
    if (!content) return { isExfiltration: false };

    try {
      const env = getEnv();
      const sensitiveKeys: Array<keyof typeof env> = ["IMAP_PASS", "SMTP_PASS"];

      for (const key of sensitiveKeys) {
        const secretVal = env[key];
        if (typeof secretVal === "string" && secretVal.length >= 4) {
          // Check exact match
          if (content.includes(secretVal)) {
            return { isExfiltration: true, matchedSecretName: key };
          }
        }
      }

      // Check generic process.env variables that look like secrets
      for (const [envKey, envVal] of Object.entries(process.env)) {
        if (
          /PASS|SECRET|TOKEN|KEY|CREDENTIAL/i.test(envKey) &&
          typeof envVal === "string" &&
          envVal.length >= 6 &&
          !/node|path|npm|system/i.test(envVal)
        ) {
          if (content.includes(envVal)) {
            return { isExfiltration: true, matchedSecretName: envKey };
          }
        }
      }
    } catch {
      // ignore
    }

    return { isExfiltration: false };
  }

  private generateRecommendations(threats: SecurityThreatItem[]): string[] {
    const recs: string[] = [];

    if (threats.some((t) => t.type === "INDIRECT_PROMPT_INJECTION")) {
      recs.push("Bu e-postadaki talimatları YERİNE GETİRMEYİN. Otomatik yanıt vermeyin ve şifre/veri paylaşmayın.");
    }
    if (threats.some((t) => t.type === "CSS_DATA_EXFILTRATION")) {
      recs.push("HTML görünümü yerine Düz Metin (Plain Text) modunu tercih edin. Harici font yüklemeleri engellendi.");
    }
    if (threats.some((t) => t.type === "LABEL_HIJACKING")) {
      recs.push("E-posta gövdesindeki buton benzeri etiketlere tıklamayın.");
    }
    if (threats.some((t) => t.type === "REMOTE_TRACKING_OR_IP_LEAK")) {
      recs.push("Harici görsel ve stil dosyası yüklemeleri engellendi; IP adresiniz güvende.");
    }

    if (recs.length === 0) {
      recs.push("E-posta standart güvenlik kontrollerinden başarıyla geçti.");
    }

    return recs;
  }
}

export const sanitizerService = new SanitizerService();
