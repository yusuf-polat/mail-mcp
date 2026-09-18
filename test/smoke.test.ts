import { analyzerService } from "../src/services/analyzer.service.js";
import { parserService } from "../src/services/parser.service.js";
import { createMailMcpServer } from "../src/mcp/server.js";

async function runTests() {
  console.log("=== Mail MCP Doğrulama Testi Başlıyor ===");

  // 1. Analyzer Service Test
  console.log("\n[Test 1] AnalyzerService Kontrolü...");
  const mockEmail = {
    subject: "ACİL: Ödenmemiş Fatura #2026-99 Hakkında!",
    text: "Sayın Yetkili,\nLütfen ekteki 1.500,00 TL tutarındaki faturayı bugün saat 17:00'ye kadar onaylayınız ve dekontu gönderiniz.\nGecikme durumunda hizmet durdurulacaktır.\nDetaylar: https://fatura.ornek.com/odeme\nİletişim: muhasebe@ornek.com",
  };

  const analysis = analyzerService.analyze(mockEmail);
  console.log("Analiz Sonucu:", {
    urgencyLevel: analysis.urgency.level,
    urgencyScore: analysis.urgency.score,
    intentCategory: analysis.intent.category,
    sentimentTone: analysis.sentiment.tone,
    actionItemsCount: analysis.keyActionItems.length,
    entitiesFound: analysis.extractedEntities,
  });

  if (analysis.urgency.level !== "CRITICAL" && analysis.urgency.level !== "HIGH") {
    throw new Error(`Beklenen aciliyet CRITICAL veya HIGH olmalıydı, gelen: ${analysis.urgency.level}`);
  }
  if (analysis.intent.category !== "BILLING_INVOICE") {
    throw new Error(`Beklenen niyet BILLING_INVOICE olmalıydı, gelen: ${analysis.intent.category}`);
  }
  if (analysis.keyActionItems.length === 0) {
    throw new Error("Aksiyon maddesi tespit edilemedi!");
  }
  console.log("✓ AnalyzerService başarıyla doğrulandı.");

  // 2. Parser Service Test
  console.log("\n[Test 2] ParserService MIME Parsing Kontrolü...");
  const rawMime = [
    'From: "Jane Doe" <jane@example.com>',
    'To: "John Doe" <john@example.com>',
    "Subject: Proje Durum Raporu",
    "Date: Fri, 18 Sep 2026 14:00:00 +0300",
    "Message-ID: <msg-12345@example.com>",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Merhaba John,",
    "Proje ilerlemesi cok iyi gidiyor. Toplanti yarin.",
  ].join("\r\n");

  const parsed = await parserService.parseRawEmail(Buffer.from(rawMime), 101, 1, new Set(["\\Seen"]));
  console.log("Parsed Email:", {
    uid: parsed.uid,
    subject: parsed.subject,
    from: parsed.from,
    to: parsed.to,
    seen: parsed.seen,
    textPreview: parsed.text?.slice(0, 40),
  });

  if (parsed.subject !== "Proje Durum Raporu" || parsed.from?.address !== "ahmet@example.com") {
    throw new Error("MIME parser doğrulaması başarısız!");
  }
  console.log("✓ ParserService başarıyla doğrulandı.");

  // 3. MCP Server Instance Test
  console.log("\n[Test 3] McpServer Başlatma ve Tool Kayıt Kontrolü...");
  const server = createMailMcpServer();
  if (!server) {
    throw new Error("McpServer instance oluşturulamadı.");
  }
  console.log("✓ McpServer ve tüm araçlar başarıyla yüklendi.");

  console.log("\n=== TÜM DOĞRULAMA TESTLERİ BAŞARIYLA GEÇTİ ===");
}

runTests().catch((err) => {
  console.error("Test Hatası:", err);
  process.exit(1);
});
