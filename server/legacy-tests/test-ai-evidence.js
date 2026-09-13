const assert = require("node:assert/strict");
const { buildAIInput } = require("./ai-evidence");
const { analyzeSecurityWithAI } = require("./ai-test-client");

async function main() {
  const url = "https://paypal.com@192.0.2.44/login";
  const cases = [
    { name: "Company claim and technical URL evidence", body: `PayPal Support: Your account has been suspended. Verify your password immediately at ${url}.`, phishing: true },
    { name: "Same technical evidence in a harmless lesson", body: `Cybersecurity lesson: ${url} is a fictional URL example. We explain how URL userinfo can disguise a destination. Never share a password. This is educational material, not an account notice or a request for action.`, phishing: false }
  ];
  let failed = 0;
  for (const sample of cases) {
    try {
      const input = buildAIInput({ body: sample.body });
      assert.equal(input.urlFindings[0].ipHost, true);
      assert.equal(input.urlFindings[0].hasAtSymbol, true);
      assert.equal(input.urlFindings[0].hostname, "192.0.2.44");
      assert.ok(input.ruleFindings.some(f => f.type === "credential_keyword"));
      const result = await analyzeSecurityWithAI(input);
      console.log(sample.name);
      console.log(JSON.stringify(result, null, 2));
      const explanation = [result.summary, ...["impersonation", "urgency", "credentialRequest", "financialRequest", "personalInformationRequest"].map(key => result[key].evidence)].join(" ");
      assert.doesNotMatch(explanation, /\bI (?:detected|found|discovered|verified)\b/i);
      if (sample.phishing) {
        assert.ok(["suspicious", "high_risk"].includes(result.classification));
        assert.equal(result.credentialRequest.detected, true);
        assert.match(explanation, /PayPal/i);
        assert.match(explanation, /URL analysis|URL findings|link checks|deterministic|supplied.*evidence/i);
        assert.match(explanation, /IP.address|IP host|numeric.*address|192\.0\.2\.44/i);
      } else {
        assert.equal(result.classification, "low_risk");
        assert.equal(result.credentialRequest.detected, false);
        assert.equal(result.impersonation.detected, false);
      }
      console.log("PASS");
    } catch (error) {
      failed++;
      console.error(error.code === "ERR_ASSERTION" ? `FAIL: ${error.message}` : `FAIL: request/validation error${Number.isInteger(error.status) ? ` HTTP ${error.status}` : ""}`);
    }
  }
  if (failed) process.exitCode = 1;
  console.log(`${cases.length - failed}/${cases.length} evidence-context tests passed.`);
}
main();
