const assert = require("node:assert/strict");
const { analyzeWithScamGuard } = require("./analyze-service");
const { analyzeSecurityWithAI } = require("./ai-test-client");

const cases = [
  ["Normal friendly message", "Hi Alex, want to meet for lunch tomorrow? No worries if you're busy. Have a great day!"],
  ["Phishing with suspicious URL", "PayPal Security Alert: Your account is suspended. Verify your password immediately at https://paypal.com@192.0.2.44/login"],
  ["Gift-card CEO scam, no URL", "This is your CEO. I am in a confidential meeting. Buy a gift card worth $500 and send me the redemption code. Keep this secret and do not call me to confirm."],
  ["Ambiguous invoice", "Hello, please review the invoice for last month's services and let me know if you have questions."],
  ["Obvious credential phishing", "Your Microsoft account will be closed. Verify your account immediately by sending your password and security code."]
];

async function main() {
  let failures = 0;
  const rows = [];
  for (const [name, message] of cases) {
    const result = await analyzeWithScamGuard(message, {}, analyzeSecurityWithAI);
    rows.push({ example: name, ...result.scores, aiStatus: result.aiStatus });
    console.log(JSON.stringify(rows.at(-1)));
    try {
      assert.equal(result.aiStatus, "available", "Live Groq response required for comparison");
      assert.ok(result.scores.aiSemanticContribution >= 0 && result.scores.aiSemanticContribution <= 25);
      assert.equal(result.risk, Math.min(100, result.scores.deterministicScore + result.scores.urlScore + result.scores.aiSemanticContribution));
    } catch (error) { failures++; console.error(error.message); }
  }
  console.table(rows);
  if (failures) process.exitCode = 1;
}
main().catch(() => { console.error("Comparison test failed."); process.exitCode = 1; });
