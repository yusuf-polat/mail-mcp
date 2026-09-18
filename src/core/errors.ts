export class MailMcpError extends Error {
  constructor(message: string, public readonly code: string = "INTERNAL_ERROR", public readonly details?: unknown) {
    super(message);
    this.name = "MailMcpError";
  }
}

export class ImapConnectionError extends MailMcpError {
  constructor(message: string, details?: unknown) {
    super(message, "IMAP_CONNECTION_ERROR", details);
    this.name = "ImapConnectionError";
  }
}

export class SmtpDeliveryError extends MailMcpError {
  constructor(message: string, details?: unknown) {
    super(message, "SMTP_DELIVERY_ERROR", details);
    this.name = "SmtpDeliveryError";
  }
}

export class EmailNotFoundError extends MailMcpError {
  constructor(identifier: string | number) {
    super(`Email not found with identifier: ${identifier}`, "EMAIL_NOT_FOUND");
    this.name = "EmailNotFoundError";
  }
}

export class VirusThreatDetectedError extends MailMcpError {
  constructor(filename: string, threatDetails: string) {
    super(
      `Zararlı yazılım / virüs tespit edildi! Güvenliğiniz için dosya indirilmedi ve derhal imha edildi. Dosya: "${filename}". Tarama Detayı: ${threatDetails}`,
      "VIRUS_THREAT_DETECTED",
      { filename, threatDetails }
    );
    this.name = "VirusThreatDetectedError";
  }
}
