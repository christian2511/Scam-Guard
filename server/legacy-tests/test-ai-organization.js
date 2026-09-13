const assert = require("node:assert/strict");
const { analyzeSecurityWithAI } = require("./ai-test-client");

const cases = [
  { name: "Microsoft impersonation, body-only claim", body: "Your Microsoft 365 account has been suspended. Send your password and security code immediately to restore access.", organization: "Microsoft", impersonation: true },
  { name: "PayPal impersonation", subject: "PayPal Security Alert", body: "Your account is locked. Send your password and security code immediately to verify your account.", organization: "PayPal", impersonation: true },
  { name: "Normal personal email", body: "Hey Jake, send me yesterday's class notes.", organization: null, impersonation: false },
  { name: "Personal email merely mentioning Amazon", body: "I bought something from Amazon yesterday. The book arrived today and I enjoyed reading it.", organization: null, impersonation: false },
  { name: "Chase department claim without deceptive request", body: "Chase Fraud Department: This is an informational account notice. We will never ask you to send us a password or security code.", organization: "Chase", impersonation: false },
  { name: "Weak unbranded context", body: "Your account preferences were updated. No action is needed.", organization: null, impersonation: false }
];

async function main() {
  let failures = 0;
  for (const [index, sample] of cases.entries()) {
    try {
      const result = await analyzeSecurityWithAI({ subject: sample.subject ?? "", sender: "", body: sample.body, urls: [] });
      console.log(JSON.stringify({ test: sample.name, claimedOrganization: result.claimedOrganization, organizationClaimConfidence: result.organizationClaimConfidence, impersonation: result.impersonation, classification: result.classification }));
      assert.equal(result.claimedOrganization, sample.organization);
      assert.equal(result.impersonation.detected, sample.impersonation);
      if (sample.organization) assert.ok(result.organizationClaimConfidence >= 0.8);
      else assert.equal(result.organizationClaimConfidence, 0);
      if (!sample.impersonation) assert.equal(result.classification, "low_risk");
      console.log("PASS");
    } catch (error) {
      failures++;
      console.error(error.code === "ERR_ASSERTION" ? `FAIL: ${sample.name}: ${error.message}` : `FAIL: ${sample.name}: request/validation error${Number.isInteger(error.status) ? ` HTTP ${error.status}` : ""}`);
    }
  }
  console.log(`${cases.length - failures}/${cases.length} claimed-organization tests passed.`);
  if (failures) process.exitCode = 1;
}
main();
