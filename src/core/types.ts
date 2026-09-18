export interface EmailAddress {
  name?: string;
  address: string;
}

export interface EmailAttachment {
  filename?: string;
  contentType: string;
  size: number;
  contentDisposition?: string;
  checksum?: string;
  cid?: string;
}

export interface EmailHeaderSummary {
  uid: number;
  seq: number;
  messageId?: string;
  subject?: string;
  from?: EmailAddress;
  to?: EmailAddress[];
  cc?: EmailAddress[];
  date?: string;
  seen: boolean;
  flagged: boolean;
  answered: boolean;
  size?: number;
}

export type SecurityThreatType =
  | "LABEL_HIJACKING"
  | "CSS_DATA_EXFILTRATION"
  | "REMOTE_TRACKING_OR_IP_LEAK"
  | "HIDDEN_CSS_STEGANOGRAPHY"
  | "INDIRECT_PROMPT_INJECTION"
  | "MALICIOUS_TAG_OR_SCRIPT";

export interface SecurityThreatItem {
  type: SecurityThreatType;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  description: string;
  snippet?: string;
}

export interface EmailSecurityReport {
  isSafe: boolean;
  threatLevel: "SAFE" | "SUSPICIOUS" | "DANGEROUS";
  threats: SecurityThreatItem[];
  hiddenTextsDetected: string[];
  sanitized: boolean;
  recommendations: string[];
}

export interface EmailDetail extends EmailHeaderSummary {
  replyTo?: EmailAddress[];
  inReplyTo?: string;
  references?: string | string[];
  text?: string;
  html?: string;
  sanitizedHtml?: string;
  securityReport?: EmailSecurityReport;
  attachments: EmailAttachment[];
  headers?: Record<string, string | string[]>;
}

export interface SearchCriteria {
  folder?: string;
  query?: string;
  from?: string;
  to?: string;
  subject?: string;
  body?: string;
  since?: string;
  before?: string;
  unreadOnly?: boolean;
  limit?: number;
}

export interface SendEmailOptions {
  to: string | string[];
  subject: string;
  bodyText: string;
  bodyHtml?: string;
  cc?: string | string[];
  bcc?: string | string[];
  replyTo?: string;
  inReplyTo?: string;
  references?: string | string[];
}

export interface ReplyEmailOptions {
  originalUid: number;
  folder?: string;
  bodyText: string;
  bodyHtml?: string;
  replyAll?: boolean;
}

export type UrgencyLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type EmailIntentCategory =
  | "INQUIRY"
  | "SUPPORT"
  | "BILLING_INVOICE"
  | "MEETING_INVITATION"
  | "SALES_MARKETING"
  | "NEWSLETTER_UPDATE"
  | "SECURITY_ALERT"
  | "SPAM_SUSPICIOUS"
  | "GENERAL";

export interface EmailAnalysisResult {
  messageId?: string;
  subject?: string;
  sender?: string;
  urgency: {
    level: UrgencyLevel;
    score: number; // 0 to 100
    reasons: string[];
  };
  intent: {
    category: EmailIntentCategory;
    confidence: number;
  };
  sentiment: {
    tone: "POSITIVE" | "NEUTRAL" | "NEGATIVE" | "URGENT" | "FRUSTRATED";
    explanation: string;
  };
  keyActionItems: string[];
  extractedEntities: {
    datesAndDeadlines: string[];
    monetaryValues: string[];
    urls: string[];
    contacts: string[];
  };
  summary: string;
  potentialPhishingOrSpamRisk: boolean;
  promptInjectionDetected?: boolean;
  securityReport?: EmailSecurityReport;
  riskWarnings: string[];
}

export interface FolderInfo {
  path: string;
  name: string;
  delimiter: string;
  specialUse?: string;
  flags?: string[];
  listed?: boolean;
  subscribed?: boolean;
}

export interface MoveEmailOptions {
  uid: number;
  destinationFolder: string;
  sourceFolder?: string;
}

export interface FlagEmailOptions {
  uid: number;
  flags: string[];
  action: "add" | "set" | "remove";
  folder?: string;
}

export interface AntivirusScanResult {
  isClean: boolean;
  scanner: string;
  sha256: string;
  threatDetails?: string;
  scanDurationMs: number;
}

export interface DownloadAttachmentResult {
  filename: string;
  contentType: string;
  size: number;
  savedPath: string;
  antivirusScan: AntivirusScanResult;
}

export interface CreateDraftOptions {
  to?: string | string[];
  subject: string;
  bodyText: string;
  bodyHtml?: string;
  cc?: string | string[];
  bcc?: string | string[];
  replyTo?: string;
  inReplyTo?: string;
  references?: string | string[];
}

export interface CalendarEventResult {
  title: string;
  description?: string;
  startDate?: string;
  endDate?: string;
  location?: string;
  meetingUrl?: string;
  attendees?: string[];
  icsContent: string;
}

export interface UnsubscribeInfo {
  hasUnsubscribe: boolean;
  listUnsubscribeHeader?: string;
  oneClickUrl?: string;
  mailtoAddress?: string;
  bodyLinks: string[];
  instructions: string;
}

export interface InboxTriageResult {
  scannedCount: number;
  timestamp: string;
  criticalAndUrgent: Array<{
    uid: number;
    subject: string;
    from?: string;
    urgencyScore: number;
    reasons: string[];
  }>;
  financialAndInvoices: Array<{
    uid: number;
    subject: string;
    from?: string;
    money?: string[];
    date?: string;
  }>;
  securityAlerts: Array<{
    uid: number;
    subject: string;
    from?: string;
    date?: string;
  }>;
  newslettersAndMarketing: Array<{
    uid: number;
    subject: string;
    from?: string;
  }>;
  keyActionItems: Array<{
    uid: number;
    subject: string;
    action: string;
  }>;
  executiveSummary: string;
}
