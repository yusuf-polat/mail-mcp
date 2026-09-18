import nodemailer, { Transporter } from "nodemailer";
import { getEnv } from "../config/env.js";
import { DataExfiltrationBlockedError, SmtpDeliveryError } from "../core/errors.js";
import { ReplyEmailOptions, SendEmailOptions } from "../core/types.js";
import { imapService } from "./imap.service.js";
import { sanitizerService } from "./sanitizer.service.js";

export class SmtpService {
  private transporter: Transporter | null = null;

  private getTransporter(): Transporter {
    if (this.transporter) return this.transporter;

    const env = getEnv();
    this.transporter = nodemailer.createTransport({
      host: env.SMTP_HOST,
      port: env.SMTP_PORT,
      secure: env.SMTP_SECURE,
      auth: {
        user: env.SMTP_USER,
        pass: env.SMTP_PASS,
      },
      pool: true,
      maxConnections: 5,
    });

    return this.transporter;
  }

  /**
   * Verifies SMTP connection configuration
   */
  public async verifyConnection(): Promise<boolean> {
    const transporter = this.getTransporter();
    try {
      await transporter.verify();
      return true;
    } catch (err) {
      throw new SmtpDeliveryError(
        `SMTP verification failed: ${err instanceof Error ? err.message : String(err)}`,
        err
      );
    }
  }

  /**
   * Sends a fresh email
   */
  public async sendEmail(options: SendEmailOptions): Promise<{
    messageId: string;
    accepted: string[];
    rejected: string[];
  }> {
    // DLP Check: Prevent Prompt Injection from leaking environment variables or secrets
    const outgoingContent = `${options.subject}\n${options.bodyText}\n${options.bodyHtml || ""}`;
    const dlpResult = sanitizerService.scanOutboundForSecrets(outgoingContent);
    if (dlpResult.isExfiltration) {
      throw new DataExfiltrationBlockedError(
        `Giden e-posta gövdesinde veya konusunda hassas çevre değişkeni/şifre (${dlpResult.matchedSecretName}) tespit edildi! Güvenlik nedeniyle gönderim engellendi.`
      );
    }

    const env = getEnv();
    const transporter = this.getTransporter();

    const fromAddress = env.SMTP_FROM_ADDRESS || env.SMTP_USER;
    const from = env.SMTP_FROM_NAME ? `"${env.SMTP_FROM_NAME}" <${fromAddress}>` : fromAddress;

    try {
      const info = await transporter.sendMail({
        from,
        to: options.to,
        subject: options.subject,
        text: options.bodyText,
        html: options.bodyHtml,
        cc: options.cc,
        bcc: options.bcc,
        replyTo: options.replyTo,
        inReplyTo: options.inReplyTo,
        references: options.references,
      });

      return {
        messageId: info.messageId,
        accepted: (info.accepted || []).map(String),
        rejected: (info.rejected || []).map(String),
      };
    } catch (err) {
      throw new SmtpDeliveryError(
        `Failed to send email to ${JSON.stringify(options.to)}: ${err instanceof Error ? err.message : String(err)}`,
        err
      );
    }
  }

  /**
   * Replies to an existing email with RFC-compliant headers (In-Reply-To, References)
   * and quoted body structure.
   */
  public async replyEmail(options: ReplyEmailOptions): Promise<{
    messageId: string;
    to: string;
    subject: string;
    quotedSender: string;
  }> {
    const folder = options.folder || "INBOX";

    // 1. Fetch original email to construct threading headers
    const original = await imapService.readEmail(options.originalUid, folder, false);

    if (!original.from?.address) {
      throw new SmtpDeliveryError(`Cannot reply: Original email (UID: ${options.originalUid}) has no valid From address.`);
    }

    const replyToAddress = original.replyTo?.[0]?.address || original.from.address;

    // 2. Build Subject
    let replySubject = original.subject || "";
    if (!replySubject.toLowerCase().startsWith("re:")) {
      replySubject = `Re: ${replySubject}`;
    }

    // 3. Threading headers
    const inReplyTo = original.messageId;
    let references: string[] = [];
    if (original.references) {
      references = Array.isArray(original.references) ? [...original.references] : [original.references];
    }
    if (original.messageId && !references.includes(original.messageId)) {
      references.push(original.messageId);
    }

    // 4. Build quoted text
    const originalDateStr = original.date ? new Date(original.date).toLocaleString() : "earlier";
    const originalSenderStr = original.from.name
      ? `${original.from.name} <${original.from.address}>`
      : original.from.address;

    const quoteHeader = `On ${originalDateStr}, ${originalSenderStr} wrote:`;
    const quotedBody = (original.text || "")
      .split("\n")
      .map((line) => `> ${line}`)
      .join("\n");

    const fullTextBody = `${options.bodyText}\n\n${quoteHeader}\n${quotedBody}`;

    let fullHtmlBody: string | undefined = undefined;
    if (options.bodyHtml) {
      fullHtmlBody = `<div>${options.bodyHtml}</div><br/><div style="border-left: 2px solid #ccc; padding-left: 8px; color: #555;"><p><strong>${quoteHeader}</strong></p>${original.html || quotedBody.replace(/\n/g, "<br/>")}</div>`;
    }

    // 5. Handle CC if replyAll is enabled
    let ccList: string[] | undefined = undefined;
    if (options.replyAll && original.to) {
      const myAddress = (getEnv().SMTP_FROM_ADDRESS || getEnv().SMTP_USER).toLowerCase();
      ccList = original.to
        .map((t) => t.address)
        .filter((addr) => addr && addr.toLowerCase() !== myAddress && addr.toLowerCase() !== replyToAddress.toLowerCase());
    }

    // 6. Send email
    const sendResult = await this.sendEmail({
      to: replyToAddress,
      subject: replySubject,
      bodyText: fullTextBody,
      bodyHtml: fullHtmlBody,
      cc: ccList,
      inReplyTo,
      references: references.join(" "),
    });

    return {
      messageId: sendResult.messageId,
      to: replyToAddress,
      subject: replySubject,
      quotedSender: originalSenderStr,
    };
  }
}

export const smtpService = new SmtpService();
