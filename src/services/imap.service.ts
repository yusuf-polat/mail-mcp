import fs from "node:fs";
import path from "node:path";
import nodemailer from "nodemailer";
import { simpleParser } from "mailparser";
import { ImapFlow, FetchMessageObject, SearchObject } from "imapflow";
import { getEnv } from "../config/env.js";
import { ImapConnectionError, EmailNotFoundError } from "../core/errors.js";
import {
  EmailDetail,
  EmailHeaderSummary,
  SearchCriteria,
  FolderInfo,
  DownloadAttachmentResult,
  CreateDraftOptions,
} from "../core/types.js";
import { parserService } from "./parser.service.js";
import { antivirusService } from "./antivirus.service.js";

export class ImapService {
  private client: ImapFlow | null = null;
  private isConnecting: boolean = false;

  private async getClient(): Promise<ImapFlow> {
    if (this.client && this.client.usable) {
      return this.client;
    }

    if (this.isConnecting) {
      // Wait shortly if already in connecting state
      await new Promise((res) => setTimeout(res, 500));
      if (this.client && this.client.usable) return this.client;
    }

    this.isConnecting = true;
    try {
      const env = getEnv();
      const client = new ImapFlow({
        host: env.IMAP_HOST,
        port: env.IMAP_PORT,
        secure: env.IMAP_SECURE,
        auth: {
          user: env.IMAP_USER,
          pass: env.IMAP_PASS,
        },
        logger: env.DEBUG ? undefined : false,
      });

      await client.connect();
      this.client = client;

      client.on("close", () => {
        this.client = null;
      });

      client.on("error", (err) => {
        if (env.DEBUG) {
          console.error("[IMAP] Connection error event:", err);
        }
      });

      return client;
    } catch (error) {
      this.client = null;
      throw new ImapConnectionError(
        `Failed to connect to IMAP server: ${error instanceof Error ? error.message : String(error)}`,
        error
      );
    } finally {
      this.isConnecting = false;
    }
  }

  /**
   * Retrieves summary list of recent emails from a mailbox folder
   */
  public async checkInbox(options: {
    folder?: string;
    limit?: number;
    unreadOnly?: boolean;
  } = {}): Promise<EmailHeaderSummary[]> {
    const client = await this.getClient();
    const folder = options.folder || "INBOX";
    const limit = Math.min(options.limit || 20, 100);

    const lock = await client.getMailboxLock(folder);
    try {
      const mailbox = client.mailbox;
      if (!mailbox || mailbox.exists === 0) {
        return [];
      }

      const results: EmailHeaderSummary[] = [];

      if (options.unreadOnly) {
        const searchResult = await client.search({ seen: false }, { uid: true });
        const uids = Array.isArray(searchResult) ? searchResult : [];
        if (uids.length === 0) return [];
        const selectedUids = uids.slice(-limit).reverse();

        for await (const msg of client.fetch(
          selectedUids.join(","),
          {
            envelope: true,
            flags: true,
            size: true,
            uid: true,
          },
          { uid: true }
        )) {
          const envelope = msg.envelope;
          results.push({
            uid: msg.uid,
            seq: msg.seq,
            messageId: envelope?.messageId,
            subject: envelope?.subject || "(No Subject)",
            from: envelope?.from?.[0]
              ? { name: envelope.from[0].name || undefined, address: envelope.from[0].address || "" }
              : undefined,
            to: envelope?.to?.map((t) => ({ name: t.name || undefined, address: t.address || "" })),
            date: envelope?.date ? envelope.date.toISOString() : undefined,
            seen: msg.flags ? msg.flags.has("\\Seen") : false,
            flagged: msg.flags ? msg.flags.has("\\Flagged") : false,
            answered: msg.flags ? msg.flags.has("\\Answered") : false,
            size: msg.size,
          });
        }
      } else {
        const total = mailbox.exists;
        const startSeq = Math.max(1, total - limit + 1);

        for await (const msg of client.fetch(
          `${startSeq}:${total}`,
          {
            envelope: true,
            flags: true,
            size: true,
            uid: true,
          }
        )) {
          const envelope = msg.envelope;
          results.push({
            uid: msg.uid,
            seq: msg.seq,
            messageId: envelope?.messageId,
            subject: envelope?.subject || "(No Subject)",
            from: envelope?.from?.[0]
              ? { name: envelope.from[0].name || undefined, address: envelope.from[0].address || "" }
              : undefined,
            to: envelope?.to?.map((t) => ({ name: t.name || undefined, address: t.address || "" })),
            date: envelope?.date ? envelope.date.toISOString() : undefined,
            seen: msg.flags ? msg.flags.has("\\Seen") : false,
            flagged: msg.flags ? msg.flags.has("\\Flagged") : false,
            answered: msg.flags ? msg.flags.has("\\Answered") : false,
            size: msg.size,
          });
        }
        results.reverse();
      }

      return results;
    } finally {
      lock.release();
    }
  }

  /**
   * Searches emails by multiple criteria
   */
  public async searchEmails(criteria: SearchCriteria): Promise<EmailHeaderSummary[]> {
    const client = await this.getClient();
    const folder = criteria.folder || "INBOX";
    const limit = Math.min(criteria.limit || 25, 100);

    const lock = await client.getMailboxLock(folder);
    try {
      const query: SearchObject = {};

      if (criteria.unreadOnly) query.seen = false;
      if (criteria.from) query.from = criteria.from;
      if (criteria.to) query.to = criteria.to;
      if (criteria.subject) query.subject = criteria.subject;
      if (criteria.body) query.body = criteria.body;
      if (criteria.since) query.since = new Date(criteria.since);
      if (criteria.before) query.before = new Date(criteria.before);

      if (criteria.query) {
        // Free text search across subject & body
        query.or = [{ subject: criteria.query }, { body: criteria.query }];
      }

      const searchResult = await client.search(query, { uid: true });
      const uids = Array.isArray(searchResult) ? searchResult : [];

      if (uids.length === 0) {
        return [];
      }

      const selectedUids = uids.slice(-limit).reverse();
      const results: EmailHeaderSummary[] = [];

      for await (const msg of client.fetch(
        selectedUids.join(","),
        {
          envelope: true,
          flags: true,
          size: true,
          uid: true,
        },
        { uid: true }
      )) {
        const envelope = msg.envelope;
        results.push({
          uid: msg.uid,
          seq: msg.seq,
          messageId: envelope?.messageId,
          subject: envelope?.subject || "(No Subject)",
          from: envelope?.from?.[0]
            ? { name: envelope.from[0].name || undefined, address: envelope.from[0].address || "" }
            : undefined,
          to: envelope?.to?.map((t) => ({ name: t.name || undefined, address: t.address || "" })),
          date: envelope?.date ? envelope.date.toISOString() : undefined,
          seen: msg.flags ? msg.flags.has("\\Seen") : false,
          flagged: msg.flags ? msg.flags.has("\\Flagged") : false,
          answered: msg.flags ? msg.flags.has("\\Answered") : false,
          size: msg.size,
        });
      }

      return results;
    } finally {
      lock.release();
    }
  }

  /**
   * Fetches and completely parses a single email by its UID
   */
  public async readEmail(
    uid: number,
    folder: string = "INBOX",
    markAsSeen: boolean = true
  ): Promise<EmailDetail> {
    const client = await this.getClient();
    const lock = await client.getMailboxLock(folder);

    try {
      let fetchedMsg: FetchMessageObject | null = null;
      let rawSource: Buffer | null = null;

      for await (const msg of client.fetch(
        String(uid),
        {
          uid: true,
          flags: true,
          source: true,
        },
        { uid: true }
      )) {
        fetchedMsg = msg;
        rawSource = msg.source || null;
        break;
      }

      if (!fetchedMsg || !rawSource) {
        throw new EmailNotFoundError(`UID ${uid} in folder "${folder}"`);
      }

      if (markAsSeen && fetchedMsg.flags && !fetchedMsg.flags.has("\\Seen")) {
        await client.messageFlagsAdd(String(uid), ["\\Seen"], { uid: true });
        fetchedMsg.flags.add("\\Seen");
      }

      return await parserService.parseRawEmail(rawSource, fetchedMsg.uid, fetchedMsg.seq, fetchedMsg.flags);
    } finally {
      lock.release();
    }
  }

  /**
   * Watches a mailbox using IMAP IDLE for real-time notifications.
   * Returns newly arrived emails when detected or when timeout expires.
   */
  public async watchNewEmails(options: {
    folder?: string;
    timeoutSeconds?: number;
  } = {}): Promise<{ newEmailsCount: number; emails: EmailHeaderSummary[]; timedOut: boolean }> {
    const client = await this.getClient();
    const folder = options.folder || "INBOX";
    const timeoutMs = Math.min(options.timeoutSeconds || 30, 300) * 1000;

    const lock = await client.getMailboxLock(folder);
    try {
      const initialCount = client.mailbox ? client.mailbox.exists : 0;
      let newEmailsDetected = false;
      let newCount = initialCount;

      const onExists = (data: { count: number; prevCount: number }) => {
        if (data.count > initialCount) {
          newEmailsDetected = true;
          newCount = data.count;
        }
      };

      client.on("exists", onExists);

      const startTime = Date.now();
      while (!newEmailsDetected && Date.now() - startTime < timeoutMs) {
        // Run idle loop in small increments
        await client.idle();
        if (newEmailsDetected) break;
        await new Promise((res) => setTimeout(res, 1000));
      }

      client.removeListener("exists", onExists);

      if (newEmailsDetected && newCount > initialCount) {
        const diff = newCount - initialCount;
        const newUidsResult = await client.search({ seq: `${initialCount + 1}:${newCount}` });
        const uids = Array.isArray(newUidsResult) ? newUidsResult : [];

        const emails: EmailHeaderSummary[] = [];
        for await (const msg of client.fetch(
          uids,
          {
            envelope: true,
            flags: true,
            size: true,
            uid: true,
          },
          { uid: true }
        )) {
          const envelope = msg.envelope;
          emails.push({
            uid: msg.uid,
            seq: msg.seq,
            messageId: envelope?.messageId,
            subject: envelope?.subject || "(No Subject)",
            from: envelope?.from?.[0]
              ? { name: envelope.from[0].name || undefined, address: envelope.from[0].address || "" }
              : undefined,
            date: envelope?.date ? envelope.date.toISOString() : undefined,
            seen: msg.flags ? msg.flags.has("\\Seen") : false,
            flagged: msg.flags ? msg.flags.has("\\Flagged") : false,
            answered: msg.flags ? msg.flags.has("\\Answered") : false,
            size: msg.size,
          });
        }

        return {
          newEmailsCount: diff,
          emails,
          timedOut: false,
        };
      }

      return {
        newEmailsCount: 0,
        emails: [],
        timedOut: true,
      };
    } finally {
      lock.release();
    }
  }

  /**
   * Lists all available mailboxes/folders in the account
   */
  public async listFolders(): Promise<FolderInfo[]> {
    const client = await this.getClient();
    const list = await client.list();
    return list.map((f) => ({
      path: f.path,
      name: f.name,
      delimiter: f.delimiter,
      specialUse: f.specialUse,
      flags: f.flags ? Array.from(f.flags) : [],
      listed: f.listed,
      subscribed: f.subscribed,
    }));
  }

  /**
   * Moves an email to a destination folder/label
   */
  public async moveEmail(
    uid: number,
    destinationFolder: string,
    sourceFolder: string = "INBOX"
  ): Promise<{ success: boolean; destination: string }> {
    const client = await this.getClient();
    const lock = await client.getMailboxLock(sourceFolder);
    try {
      await client.messageMove(String(uid), destinationFolder, { uid: true });
      return { success: true, destination: destinationFolder };
    } finally {
      lock.release();
    }
  }

  /**
   * Adds, sets, or removes flags (e.g. \\Flagged, \\Seen, \\Answered) on an email
   */
  public async flagEmail(
    uid: number,
    flags: string[],
    action: "add" | "set" | "remove" = "add",
    folder: string = "INBOX"
  ): Promise<{ success: boolean; flags: string[]; action: string }> {
    const client = await this.getClient();
    const lock = await client.getMailboxLock(folder);
    try {
      if (action === "add") {
        await client.messageFlagsAdd(String(uid), flags, { uid: true });
      } else if (action === "remove") {
        await client.messageFlagsRemove(String(uid), flags, { uid: true });
      } else if (action === "set") {
        await client.messageFlagsSet(String(uid), flags, { uid: true });
      }
      return { success: true, flags, action };
    } finally {
      lock.release();
    }
  }

  /**
   * Deletes an email (moves to Trash or permanently deletes)
   */
  public async deleteEmail(
    uid: number,
    permanent: boolean = false,
    folder: string = "INBOX"
  ): Promise<{ success: boolean; action: string }> {
    const client = await this.getClient();
    if (permanent) {
      const lock = await client.getMailboxLock(folder);
      try {
        await client.messageDelete(String(uid), { uid: true });
        return { success: true, action: "permanently_deleted" };
      } finally {
        lock.release();
      }
    } else {
      const folders = await client.list();
      const trashFolder =
        folders.find((f) => f.specialUse === "\\Trash")?.path ||
        folders.find(
          (f) =>
            f.path.toLowerCase().includes("trash") ||
            f.path.toLowerCase().includes("çöp")
        )?.path ||
        "[Gmail]/Trash";

      const moveRes = await this.moveEmail(uid, trashFolder, folder);
      return { success: true, action: `moved_to_trash: ${moveRes.destination}` };
    }
  }

  /**
   * Downloads an attachment from an email and saves it to local disk
   */
  public async downloadAttachment(
    uid: number,
    attachmentIdentifier: string | number,
    targetDir: string = "./downloads",
    folder: string = "INBOX"
  ): Promise<DownloadAttachmentResult> {
    const client = await this.getClient();
    const lock = await client.getMailboxLock(folder);
    let rawSource: Buffer | null = null;
    try {
      for await (const msg of client.fetch(String(uid), { source: true }, { uid: true })) {
        rawSource = msg.source || null;
        break;
      }
    } finally {
      lock.release();
    }

    if (!rawSource) {
      throw new EmailNotFoundError(`UID ${uid} in folder "${folder}"`);
    }

    const parsed = await simpleParser(rawSource);
    if (!parsed.attachments || parsed.attachments.length === 0) {
      throw new Error(`E-postada herhangi bir ek dosya bulunamadı (UID: ${uid}).`);
    }

    let attachment = null;
    if (typeof attachmentIdentifier === "number") {
      attachment = parsed.attachments[attachmentIdentifier];
    } else {
      const targetName = attachmentIdentifier.toLowerCase();
      attachment =
        parsed.attachments.find(
          (a) => a.filename && a.filename.toLowerCase() === targetName
        ) ||
        parsed.attachments.find(
          (a) => a.filename && a.filename.toLowerCase().includes(targetName)
        );
    }

    if (!attachment) {
      const available = parsed.attachments
        .map((a, i) => `[${i}] ${a.filename || "adsız"}`)
        .join(", ");
      throw new Error(
        `Belirtilen ek ("${attachmentIdentifier}") bulunamadı. Mevcut ekler: ${available}`
      );
    }

    const safeFilename = attachment.filename
      ? attachment.filename.replace(/[/\\?%*:|"<>]/g, "_")
      : `attachment_${Date.now()}`;

    // 1. Mandatory Quarantine Staging Area
    const quarantineDir = path.resolve("./.quarantine");
    if (!fs.existsSync(quarantineDir)) {
      fs.mkdirSync(quarantineDir, { recursive: true });
    }

    const tempScanFile = path.join(
      quarantineDir,
      `scan_${Date.now()}_${Math.random().toString(36).slice(2, 8)}_${safeFilename}`
    );

    // Write bytes only to quarantine space first
    fs.writeFileSync(tempScanFile, attachment.content);

    // 2. Mandatory Multi-Layer Antivirus Scanning (Windows Defender + Heuristics)
    let scanResult;
    try {
      scanResult = await antivirusService.scanFile(
        tempScanFile,
        attachment.filename || safeFilename
      );
    } catch (scanError) {
      // Ensure infected / suspicious file is immediately expunged from disk
      if (fs.existsSync(tempScanFile)) {
        try {
          fs.unlinkSync(tempScanFile);
        } catch {
          // ignore unlink error
        }
      }
      throw scanError;
    }

    // 3. Move cleanly to final destination only after 100% verified clean
    const resolvedDir = path.resolve(targetDir);
    if (!fs.existsSync(resolvedDir)) {
      fs.mkdirSync(resolvedDir, { recursive: true });
    }

    const filePath = path.join(resolvedDir, safeFilename);
    fs.renameSync(tempScanFile, filePath);

    return {
      filename: safeFilename,
      contentType: attachment.contentType,
      size: attachment.size,
      savedPath: filePath,
      antivirusScan: scanResult,
    };
  }

  /**
   * Appends an email draft into the Drafts mailbox
   */
  public async createDraft(
    options: CreateDraftOptions
  ): Promise<{ success: boolean; folder: string }> {
    const client = await this.getClient();
    const env = getEnv();

    const fromAddress = env.SMTP_FROM_ADDRESS || env.SMTP_USER;
    const from = env.SMTP_FROM_NAME ? `"${env.SMTP_FROM_NAME}" <${fromAddress}>` : fromAddress;

    const mailer = nodemailer.createTransport({
      streamTransport: true,
      newline: "windows",
    });

    const info = await mailer.sendMail({
      from,
      to: options.to,
      cc: options.cc,
      bcc: options.bcc,
      subject: options.subject,
      text: options.bodyText,
      html: options.bodyHtml,
      replyTo: options.replyTo,
      inReplyTo: options.inReplyTo,
      references: options.references,
    });

    const chunks: Buffer[] = [];
    for await (const chunk of info.message as any) {
      chunks.push(Buffer.from(chunk));
    }
    const rawMime = Buffer.concat(chunks);

    const folders = await client.list();
    const draftsFolder =
      folders.find((f) => f.specialUse === "\\Drafts")?.path ||
      folders.find(
        (f) =>
          f.path.toLowerCase().includes("draft") ||
          f.path.toLowerCase().includes("taslak")
      )?.path ||
      "[Gmail]/Drafts";

    await client.append(draftsFolder, rawMime, ["\\Draft", "\\Seen"]);

    return {
      success: true,
      folder: draftsFolder,
    };
  }

  /**
   * Gracefully close connection
   */
  public async disconnect(): Promise<void> {
    if (this.client) {
      try {
        await this.client.logout();
      } catch {
        // ignore logout failure
      }
      this.client = null;
    }
  }
}

export const imapService = new ImapService();
