import fs from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface VersionStatus {
  isUpToDate: boolean;
  currentVersion: string;
  remoteVersion?: string;
  localCommit?: string;
  remoteCommit?: string;
  updated: boolean;
  message: string;
}

export class UpdaterService {
  private repoOwner = "yusuf-polat";
  private repoName = "mail-mcp";
  private branch = "master";

  /**
   * Retrieves local package.json version
   */
  public getLocalVersion(): string {
    try {
      const pkgPath = path.resolve(process.cwd(), "package.json");
      if (fs.existsSync(pkgPath)) {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
        return pkg.version || "1.0.0";
      }
    } catch {
      // fallback
    }
    return "1.0.0";
  }

  /**
   * Checks GitHub repository to verify if current codebase matches latest GitHub release/commit.
   */
  public async checkVersion(autoPull = false): Promise<VersionStatus> {
    const currentVersion = this.getLocalVersion();
    let localCommit: string | undefined = undefined;
    let remoteCommit: string | undefined = undefined;
    let remoteVersion: string | undefined = undefined;
    let isUpToDate = true;
    let updated = false;

    // 1. Try Git-based check if running in a Git clone
    try {
      const isGitRepo = fs.existsSync(path.resolve(process.cwd(), ".git"));
      if (isGitRepo) {
        // Get local HEAD commit
        const { stdout: headOut } = await execFileAsync("git", ["rev-parse", "HEAD"], { timeout: 3000 });
        localCommit = headOut.trim().slice(0, 7);

        // Fetch latest from origin master
        try {
          await execFileAsync("git", ["fetch", "origin", this.branch], { timeout: 5000 });
          const { stdout: remoteOut } = await execFileAsync("git", ["rev-parse", `origin/${this.branch}`], {
            timeout: 3000,
          });
          remoteCommit = remoteOut.trim().slice(0, 7);

          if (localCommit !== remoteCommit) {
            isUpToDate = false;

            if (autoPull) {
              // Automatically pull latest updates and security patches
              await execFileAsync("git", ["pull", "origin", this.branch], { timeout: 10000 });
              updated = true;
              isUpToDate = true;
            }
          }
        } catch {
          // If network / git fetch fails, fallback to HTTP check
        }
      }
    } catch {
      // Ignore git errors
    }

    // 2. HTTP Fallback check via GitHub raw API
    if (!remoteVersion) {
      try {
        const rawUrl = `https://raw.githubusercontent.com/${this.repoOwner}/${this.repoName}/${this.branch}/package.json`;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 3500);

        const response = await fetch(rawUrl, {
          signal: controller.signal,
          headers: { "User-Agent": "mail-mcp-updater" },
        });
        clearTimeout(timeoutId);

        if (response.ok) {
          const remotePkg = (await response.json()) as { version?: string };
          remoteVersion = remotePkg.version;
          if (remoteVersion && remoteVersion !== currentVersion) {
            isUpToDate = false;
          }
        }
      } catch {
        // Offline or timeout
      }
    }

    let message = "";
    if (updated) {
      message = `Mail-MCP sunucusu GitHub'daki en son güvenlik güncellemesine (${remoteCommit || remoteVersion}) otomatik olarak güncellendi.`;
    } else if (isUpToDate) {
      message = `Mail-MCP güncel sürümde çalışıyor (v${currentVersion}${localCommit ? ` - Commit: ${localCommit}` : ""}).`;
    } else {
      message = `DİKKAT: GitHub'da yeni bir güvenlik güncellemesi mevcut! (Mevcut: ${currentVersion}${localCommit ? ` [${localCommit}]` : ""}, GitHub: ${remoteVersion || remoteCommit}).`;
    }

    return {
      isUpToDate,
      currentVersion,
      remoteVersion,
      localCommit,
      remoteCommit,
      updated,
      message,
    };
  }

  /**
   * Verifies and syncs with GitHub before running.
   */
  public async ensureLatestVersion(): Promise<VersionStatus> {
    try {
      const status = await this.checkVersion(true);
      if (status.updated) {
        console.error(`[Mail-MCP / Updater] ⚡ ${status.message}`);
      } else if (!status.isUpToDate) {
        console.error(`[Mail-MCP / Security Warning] ⚠️ ${status.message}`);
      } else {
        console.error(`[Mail-MCP / Version] ✓ ${status.message}`);
      }
      return status;
    } catch (err) {
      console.error(`[Mail-MCP / Version] Versiyon kontrolü atlandı (çevrimdışı/hata):`, err);
      return {
        isUpToDate: true,
        currentVersion: this.getLocalVersion(),
        updated: false,
        message: "Versiyon kontrolü yapılamadı, yerel sürümle devam ediliyor.",
      };
    }
  }
}

export const updaterService = new UpdaterService();
