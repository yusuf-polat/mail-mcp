import dotenv from "dotenv";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

// Load environment variables from project root .env file regardless of current working directory
const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, "../../.env") });
dotenv.config();

const envSchema = z.object({
  // IMAP Configuration
  IMAP_HOST: z.string().min(1, "IMAP_HOST is required (e.g., imap.gmail.com)"),
  IMAP_PORT: z.coerce.number().default(993),
  IMAP_SECURE: z
    .string()
    .optional()
    .transform((val) => val === undefined || val === "true" || val === "1"),
  IMAP_USER: z.string().min(1, "IMAP_USER is required"),
  IMAP_PASS: z.string().min(1, "IMAP_PASS is required"),

  // SMTP Configuration
  SMTP_HOST: z.string().min(1, "SMTP_HOST is required (e.g., smtp.gmail.com)"),
  SMTP_PORT: z.coerce.number().default(465),
  SMTP_SECURE: z
    .string()
    .optional()
    .transform((val) => val === undefined || val === "true" || val === "1"),
  SMTP_USER: z.string().min(1, "SMTP_USER is required"),
  SMTP_PASS: z.string().min(1, "SMTP_PASS is required"),
  SMTP_FROM_NAME: z.string().optional().default("Mail MCP Assistant"),
  SMTP_FROM_ADDRESS: z.string().email().optional(),

  // Operational
  DEBUG: z
    .string()
    .optional()
    .transform((val) => val === "true" || val === "1"),
});

export type EnvConfig = z.infer<typeof envSchema>;

let cachedEnv: EnvConfig | null = null;

export function getEnv(): EnvConfig {
  if (cachedEnv) {
    return cachedEnv;
  }

  const result = envSchema.safeParse(process.env);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join(".")}: ${i.message}`)
      .join("\n");
    throw new Error(
      `[Mail-MCP] Invalid configuration in environment variables:\n${issues}\n\nPlease check your .env file or MCP settings.`
    );
  }

  cachedEnv = result.data;
  return cachedEnv;
}

export function isEnvConfigured(): boolean {
  try {
    getEnv();
    return true;
  } catch {
    return false;
  }
}
