import { imapService } from "../src/services/imap.service.js";
import { smtpService } from "../src/services/smtp.service.js";

async function testLiveConnection() {
  console.log("=== Gmail Canlı Bağlantı Testi ===");

  // 1. SMTP Test
  console.log("\n[1/2] SMTP bağlantısı test ediliyor...");
  try {
    const smtpOk = await smtpService.verifyConnection();
    console.log("✓ SMTP Doğrulaması BAŞARILI! (E-posta gönderme hazır)");
  } catch (err) {
    console.error("✗ SMTP Hatası:", err instanceof Error ? err.message : err);
  }

  // 2. IMAP Test
  console.log("\n[2/2] IMAP bağlantısı ve gelen kutusu kontrol ediliyor...");
  try {
    const emails = await imapService.checkInbox({ limit: 3 });
    console.log(`✓ IMAP Doğrulaması BAŞARILI! En son ${emails.length} e-posta listelendi.`);
    for (const m of emails) {
      console.log(`  - [UID: ${m.uid}] ${m.from?.address || "Bilinmiyor"}: "${m.subject}" (${m.seen ? "Okundu" : "Okunmadı"})`);
    }
  } catch (err) {
    console.error("✗ IMAP Hatası:", err instanceof Error ? err.message : err);
  } finally {
    await imapService.disconnect();
  }

  console.log("\n=== Test Tamamlandı ===");
}

testLiveConnection().catch(console.error);
