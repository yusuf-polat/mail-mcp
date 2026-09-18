import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { AntivirusScanResult } from "../core/types.js";
import { VirusThreatDetectedError } from "../core/errors.js";

const execFileAsync = promisify(execFile);

// High risk executable / script extensions commonly used in malware
const DANGEROUS_EXTENSIONS = new Set([
  ".exe",
  ".scr",
  ".bat",
  ".cmd",
  ".vbs",
  ".vbe",
  ".js",
  ".jse",
  ".wsf",
  ".wsh",
  ".hta",
  ".cpl",
  ".msc",
  ".msi",
  ".msp",
  ".pif",
  ".com",
  ".gadget",
  ".ps1",
  ".ps1xml",
  ".ps2",
  ".psc1",
  ".psc2",
  ".reg",
  ".inf",
  ".scf",
  ".lnk",
  ".jar",
]);

// Standard EICAR test antivirus string
const EICAR_SIGNATURE = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

export class AntivirusService {
  private defenderPath: string | null = null;
  private searchedDefender = false;

  /**
   * Locates Windows Defender CLI executable (MpCmdRun.exe)
   */
  private getDefenderPath(): string | null {
    if (this.searchedDefender) return this.defenderPath;
    this.searchedDefender = true;

    // Check platform directory first (latest platform engine)
    const platformBase = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform";
    if (fs.existsSync(platformBase)) {
      try {
        const subdirs = fs.readdirSync(platformBase).sort().reverse();
        for (const dir of subdirs) {
          const candidate = path.join(platformBase, dir, "MpCmdRun.exe");
          if (fs.existsSync(candidate)) {
            this.defenderPath = candidate;
            return candidate;
          }
        }
      } catch {
        // ignore read error
      }
    }

    // Check default program files
    const programFilesPath = "C:\\Program Files\\Windows Defender\\MpCmdRun.exe";
    if (fs.existsSync(programFilesPath)) {
      this.defenderPath = programFilesPath;
      return programFilesPath;
    }

    return null;
  }

  /**
   * Scans a file with heuristic checks and Windows Defender.
   * If any virus/threat is detected, throws VirusThreatDetectedError.
   */
  public async scanFile(filePath: string, originalFilename: string): Promise<AntivirusScanResult> {
    const startTime = Date.now();

    if (!fs.existsSync(filePath)) {
      throw new Error(`Taranacak dosya diskte bulunamadı: ${filePath}`);
    }

    const fileBuffer = fs.readFileSync(filePath);

    // 1. Calculate SHA-256
    const sha256 = crypto.createHash("sha256").update(fileBuffer).digest("hex");

    // 2. Pre-flight Heuristic Checks
    const ext = path.extname(originalFilename).toLowerCase();
    const parts = originalFilename.split(".");
    
    // Check double extension trick (e.g. fatura.pdf.exe)
    if (parts.length > 2) {
      const lastExt = `.${parts[parts.length - 1].toLowerCase()}`;
      const secondLastExt = `.${parts[parts.length - 2].toLowerCase()}`;
      if (DANGEROUS_EXTENSIONS.has(lastExt)) {
        throw new VirusThreatDetectedError(
          originalFilename,
          `Şüpheli çift dosya uzantısı tespit edildi (${secondLastExt}${lastExt}). Potansiyel truva atı (Trojan) riski!`
        );
      }
    }

    // Direct executable extension check
    if (DANGEROUS_EXTENSIONS.has(ext)) {
      throw new VirusThreatDetectedError(
        originalFilename,
        `Yüksek riskli yürütülebilir/komut dosyası uzantısı engellendi (${ext}).`
      );
    }

    // Check EICAR standard test string
    if (fileBuffer.includes(Buffer.from(EICAR_SIGNATURE))) {
      throw new VirusThreatDetectedError(
        originalFilename,
        "EICAR-Standard-Antivirus-Test-File zararlı yazılım imzası tespit edildi!"
      );
    }

    // 3. Windows Defender Active Engine Scan
    const defender = this.getDefenderPath();
    let scannerName = "Heuristic Signature Engine";

    if (defender) {
      scannerName = "Microsoft Defender Antivirus (MpCmdRun)";
      try {
        // MpCmdRun.exe -Scan -ScanType 3 -File "<path>"
        const { stdout, stderr } = await execFileAsync(defender, [
          "-Scan",
          "-ScanType",
          "3",
          "-File",
          filePath,
        ]);

        const combinedOutput = `${stdout || ""} ${stderr || ""}`;
        if (
          combinedOutput.toLowerCase().includes("threat") &&
          !combinedOutput.toLowerCase().includes("found no threats")
        ) {
          throw new VirusThreatDetectedError(
            originalFilename,
            `Windows Defender taramasında tehdit algılandı: ${combinedOutput.trim()}`
          );
        }
      } catch (err: any) {
        // Exit code 2 indicates threat found in MpCmdRun
        if (err.code === 2 || (err.stdout && err.stdout.includes("threat"))) {
          throw new VirusThreatDetectedError(
            originalFilename,
            `Windows Defender zararlı yazılım tespit etti ve dosyayı engelledi! (Kod: ${err.code})`
          );
        }
        // If it was another error (non-threat), log and allow if file wasn't deleted by AV
        if (!fs.existsSync(filePath)) {
          throw new VirusThreatDetectedError(
            originalFilename,
            "Dosya antivirüs motoru tarafından karantinaya alındı veya silindi."
          );
        }
      }
    }

    const scanDurationMs = Date.now() - startTime;

    return {
      isClean: true,
      scanner: scannerName,
      sha256,
      scanDurationMs,
    };
  }
}

export const antivirusService = new AntivirusService();
