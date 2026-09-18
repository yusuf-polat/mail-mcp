# 📬 Enterprise Mail MCP Server

[![Model Context Protocol](https://img.shields.io/badge/MCP-Standard%20v1.0-blue?style=flat-square)](https://modelcontextprotocol.io/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8%2B-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D20.0.0-339933?style=flat-square&logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Security](https://img.shields.io/badge/Antivirus-Defender%20Protected-brightgreen?style=flat-square)](https://github.com/yusuf-polat/mail-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)

An enterprise-ready, autonomous **Model Context Protocol (MCP)** server that connects Large Language Model (LLM) agents—including **Antigravity IDE**, **Claude Desktop**, and other MCP-compliant clients—to email accounts via standard **IMAP** and **SMTP** protocols.

Equipped with autonomous mailbox triage, thread-aware smart drafting, RFC 5545 calendar event generation, marketing unsubscribe link detection, and a **zero-trust multi-layer antivirus engine** that scans all attachments before disk persistence.

---

## 🌟 Key Capabilities

### 🛡️ Zero-Trust Security, Sanitization & Antivirus Protection
* **HTML/CSS Zero-Day & PortSwigger Exploit Neutralization:** Automatically detects and strips dangerous CSS font exfiltration (`@font-face`, `unicode-range`, `descent-override`), Label Hijacking (`<label for="...">` attacking webmail UI buttons), and remote IP tracking (`image-set()`, `@import`, remote stylesheets).
* **AI Prompt Injection & Steganography Shield:** Detects stealth text hidden via CSS (`opacity: 0`, `font-size: 0`, `display: none`, `::before`/`::after` pseudo-elements) intended to deceive AI readers, and blocks indirect prompt injection payloads attempting to compromise credentials.
* **Outbound Data Loss Prevention (DLP):** Monitors all outgoing messages (`send_email`, `reply_email`) to guarantee environment secrets (e.g. `IMAP_PASS`, `SMTP_PASS`, API tokens) can never be exfiltrated via email.
* **Mandatory Antivirus Scanning:** Every file attachment requested for download is first isolated in a secure quarantine staging area (`.quarantine/`) and scanned by **Microsoft Defender Antivirus (`MpCmdRun.exe`)** and heuristic engines.
* **Malware & Double Extension Defense:** Detects executable tricks (`.pdf.exe`, `.docx.scr`), script blocks, and standard malware signatures.
* **Instant Destruction on Threat:** Any flagged attachment is immediately expunged from storage and blocked with a `VirusThreatDetectedError`. Safe files are verified with SHA-256 hashes.

### 📬 Complete Mailbox Operations & Organization
* **Read & Search:** List recent emails (`check_inbox`), search with multi-criteria filters (`search_emails`), and inspect complete MIME details (`read_email`).
* **Folder & Label Management:** Enumerate mailboxes (`list_folders`), move messages between folders (`move_email`), star/flag/read-unread (`flag_email`), and safely trash or delete (`delete_email`).
* **Attachment Downloader:** Verified, secure attachment extraction (`download_attachment`).

### ✍️ Intelligent Dispatch & Smart Drafts
* **Direct Send & Reply:** RFC 2822-compliant message delivery with HTML, CC, BCC, and thread-aware headers (`In-Reply-To`, `References`).
* **Non-Destructive AI Drafts (`create_draft`):** Generates proposed emails directly inside the server's **`Drafts`** folder, allowing human-in-the-loop review before sending.

### 🧠 Semantic Email Intelligence & Triage
* **Heuristic Analysis (`analyze_email`):** Computes urgency scores (0–100), extracts action items, classifies intent (`BILLING_INVOICE`, `SECURITY_ALERT`, `SUPPORT`, etc.), detects financial entities, and checks phishing indicators.
* **Autonomous Inbox Triage (`triage_inbox`):** Scans the latest messages and compiles an executive triage report highlighting critical tasks, pending payments, security events, and newsletters.

### 📅 Calendar & Productivity Tools
* **Meeting Extractor (`extract_calendar_event`):** Parses dates, times, attendees, and virtual meeting links (Google Meet, Zoom, Microsoft Teams) to generate RFC 5545 standard **`.ics`** iCalendar payloads.
* **Unsubscribe Assistant (`find_unsubscribe_links`):** Extracts RFC 2369 `List-Unsubscribe` headers (one-click URLs and mailto) along with in-body unsubscribe links.
* **Real-Time Notification (`watch_new_emails`):** Leverages IMAP IDLE for instant arrival notifications without polling overhead.

---

## 🏗️ Architecture Overview

```
                          ┌────────────────────────────┐
                          │   LLM Agent / MCP Client   │
                          │ (Antigravity / Claude / AI)│
                          └─────────────┬──────────────┘
                                        │  JSON-RPC (stdio)
                                        ▼
                          ┌────────────────────────────┐
                          │    Mail MCP Core Server    │
                          └──────┬──────────────┬──────┘
                                 │              │
           ┌─────────────────────┴───┐     ┌────┴────────────────────┐
           │   IMAP / SMTP Services  │     │ Security & Intelligence │
           │ (ImapFlow & Nodemailer) │     │ (Analyzer & Antivirus)  │
           └─────────────┬───────────┘     └────┬────────────────────┘
                         │                      │
        ┌────────────────┴───────────────┐      ├─► Microsoft Defender (MpCmdRun)
        │  Mail Providers (TLS / SSL)    │      ├─► Double-Extension Defense
        │  • Gmail                       │      ├─► EICAR & Heuristic Checks
        │  • Microsoft Outlook / 365     │      ├─► Quarantine Staging Area
        │  • Custom IMAP/SMTP Servers    │      └─► SHA-256 Hash Verification
        └────────────────────────────────┘
```

---

## 🛠️ Tool Catalog Reference

| Tool Name | Scope | Description |
| :--- | :--- | :--- |
| `check_inbox` | Reading | Retrieves recent message headers with pagination and unread filtering. |
| `search_emails` | Reading | Searches emails by query, sender, recipient, subject, body, or dates. |
| `read_email` | Reading | Fetches and parses complete MIME email details (HTML, text, headers, attachments). |
| `list_folders` | Organization | Lists all account mailboxes, special-use flags, and paths. |
| `move_email` | Organization | Moves an email by UID to a destination folder or label. |
| `flag_email` | Organization | Adds, removes, or sets IMAP flags (`\Flagged`, `\Seen`, etc.). |
| `delete_email` | Organization | Moves message to Trash or permanently purges it. |
| `download_attachment`| Attachments | Scans with Windows Defender and saves verified attachments to disk. |
| `send_email` | Dispatch | Sends a new email via SMTP with HTML/Text support. |
| `reply_email` | Dispatch | Replies to an existing thread maintaining message references. |
| `create_draft` | Dispatch | Saves an email draft to the `Drafts` folder for manual review. |
| `verify_smtp_connection`| Diagnostic | Validates SMTP server credentials and connectivity. |
| `analyze_email` | Intelligence | Computes urgency, intent, sentiment, action items, and security warnings. |
| `triage_inbox` | Intelligence | Audits recent inbox activity into grouped actionable categories. |
| `extract_calendar_event`| Calendar | Converts meeting text/dates/links into standard `.ics` format. |
| `find_unsubscribe_links`| Unsubscribe | Identifies `List-Unsubscribe` headers and opt-out links. |
| `watch_new_emails` | Monitoring | Holds an IMAP IDLE connection to wait for incoming mail. |

---

## 🚀 Getting Started

### 1. Prerequisites
- **Node.js**: `v20.0.0` or higher
- **Package Manager**: `npm` (v9+)
- An active email account supporting IMAP/SMTP (e.g. Gmail, Outlook, Yahoo, or private webmail)

### 2. Installation
```bash
git clone https://github.com/yusuf-polat/mail-mcp.git
cd mail-mcp
npm install
```

### 3. Environment Configuration
Copy the provided `.env.example` file to `.env`:
```bash
cp .env.example .env
```

Edit `.env` with your email account configuration:

```env
# --- IMAP Configuration (Reading & Real-Time Monitoring) ---
IMAP_HOST=imap.gmail.com
IMAP_PORT=993
IMAP_SECURE=true
IMAP_USER=your_email@example.com
IMAP_PASS=your_16_digit_app_password

# --- SMTP Configuration (Sending & Replying) ---
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=your_email@example.com
SMTP_PASS=your_16_digit_app_password

# --- Sender Info ---
SMTP_FROM_NAME="AI Mail Assistant"
# SMTP_FROM_ADDRESS=your_email@example.com

# --- Debug Mode ---
DEBUG=false
```

> [!IMPORTANT]
> **Gmail Users:** Do not use your personal password. Enable **2-Step Verification** on your Google Account, generate a 16-character **[App Password](https://myaccount.google.com/apppasswords)**, and verify that **[IMAP Access](https://mail.google.com/mail/u/0/#settings/fwdandpop)** is enabled.

### 4. Build
Compile TypeScript to production-ready JavaScript in `dist/`:
```bash
npm run build
```

### 5. Verification Test
Validate that the services, MIME parsers, and heuristic analyzer initialize properly:
```bash
npx tsx test/smoke.test.ts
```

---

## 🔌 MCP Client Integration

### Antigravity IDE
Add the server definition to `%USERPROFILE%\.gemini\config\mcp_config.json` (Windows) or `~/.gemini/config/mcp_config.json` (macOS / Linux):

```json
{
  "mcpServers": {
    "mail": {
      "command": "node",
      "args": [
        "C:\\path\\to\\mail-mcp\\dist\\index.js"
      ]
    }
  }
}
```

### Claude Desktop
Add the server definition to your `claude_desktop_config.json`:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "mail": {
      "command": "node",
      "args": [
        "/absolute/path/to/mail-mcp/dist/index.js"
      ]
    }
  }
}
```

---

## 🔒 Security and Privacy Best Practices

1. **Strict Secrets Isolation:** The `.env` file is excluded via `.gitignore`. Never commit credentials, tokens, or app passwords to version control.
2. **Read-Only Option:** If sending or message deletion capabilities are not required in your environment, permissions can be restricted at the mail provider level.
3. **Quarantine Execution:** Downloaded attachments are placed in `.quarantine/` and scanned prior to delivery.
4. **Draft-First Workflows:** For critical correspondence, use `create_draft` instead of `send_email` to maintain human review.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
