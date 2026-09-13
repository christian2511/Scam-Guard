const assert = require("node:assert/strict");
const { analyzeSecurityWithAI } = require("./ai-test-client");
const samples = [
  { name: "Misleading PayPal link", body: "PayPal Security Alert: Your account is suspended. Verify your password immediately at https://paypal.com@192.0.2.44/login", action: /app|directly|already know|trusted|official/i },
  { name: "School account", body: "Your school account is locked. Send us your password and security code immediately to restore access.", action: /school|trusted|already trust/i },
  { name: "Gift-card request", body: "This is your CEO. Buy a gift card for $500 and send me the code. Keep this secret and do not call me.", action: /do not|don't|don’t|never/i },
  { name: "Friendly message", body: "Hi Jake, would you like to meet for lunch tomorrow? No worries if you're busy.", action: /./ }
];
async function main() {
  let failed = 0;
  for (const sample of samples) {
    try {
      const result = await analyzeSecurityWithAI({ body: sample.body });
      console.log(JSON.stringify({ test: sample.name, summary: result.summary, recommendation: result.recommendation }, null, 2));
      assert.ok(result.summary.trim().split(/\s+/).length <= 65, "Summary exceeds word budget");
      assert.ok(result.recommendation.trim().split(/\s+/).length <= 35, "Recommendation exceeds word budget");
      assert.doesNotMatch(result.summary + result.recommendation, /ip_host|at_symbol|credential solicitation|threat actor|attack vector|definitely malicious|definitely safe|pretends to be|classic.*scam|likely malicious|steal credentials/i);
      assert.match(result.recommendation, sample.action);
      if (sample.name === "Friendly message") assert.equal(result.classification, "low_risk");
      console.log("PASS");
    } catch (error) {
      failed++;
      console.error(error.code === "ERR_ASSERTION" ? error.message : "AI language test request failed.");
    }
  }
  console.log(`${samples.length - failed}/${samples.length} language tests passed.`);
  if (failed) process.exitCode = 1;
}
main();
