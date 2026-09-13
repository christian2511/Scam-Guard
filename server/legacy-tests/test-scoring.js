const assert = require("node:assert/strict");
const { analyzeMessage, collectDeterministicEvidence } = require("./detector");
const { calculateScore } = require("./scoring");
const { analyzeWithScamGuard } = require("./analyze-service");
const { analysisSchema } = require("./ai-analysis-schema");
const { reconcileClassification } = require("./ai-security-analysis");

function fixture(schema) {
  if (schema.type === "object") return Object.fromEntries(Object.entries(schema.properties).map(([key, child]) => [key, fixture(child)]));
  if (Array.isArray(schema.type)) return null;
  if (schema.enum) return schema.enum[0];
  return schema.type === "boolean" ? false : schema.type === "string" ? "" : 0;
}

async function main() {
  const ai = fixture(analysisSchema);
  ai.classification = "high_risk";
  ai.socialEngineeringRisk = 100;
  for (const [score, expected] of [[0, "low_risk"], [29, "low_risk"], [30, "suspicious"], [59, "suspicious"], [60, "high_risk"], [100, "high_risk"]]) {
    const reconciled = reconcileClassification({ ...ai, classification: "suspicious", socialEngineeringRisk: score });
    assert.equal(reconciled.classification, expected);
    assert.equal(reconciled.socialEngineeringRisk, score);
  }
  assert.equal(reconcileClassification({ ...ai, uncertain: true }).classification, "uncertain");
  const empty = collectDeterministicEvidence("Hello friend.");
  assert.equal(calculateScore(empty, ai).finalScore, 25, "AI alone cannot dominate the score");
  ai.uncertain = true;
  assert.equal(calculateScore(empty, ai).aiSemanticContribution, 13);
  ai.uncertain = false;
  for (const message of ["Hello friend", "urgent password http://192.0.2.1", "PayPal https://paypal.com@192.0.2.44/login", "urgent immediately password login gift card bitcoin police arrest"]) {
    const evidence = collectDeterministicEvidence(message);
    assert.equal(calculateScore(evidence).finalScore, analyzeMessage(message).risk);
    assert.ok(calculateScore(evidence, ai).finalScore <= 100);
    assert.ok(calculateScore(evidence, ai).finalScore >= analyzeMessage(message).risk);
  }
  for (const fail of [async () => { throw new Error("provider unavailable"); }, async () => ({ socialEngineeringRisk: 100 })]) {
    const result = await analyzeWithScamGuard("urgent password", {}, fail);
    assert.equal(result.aiStatus, "unavailable");
    assert.equal(result.risk, analyzeMessage("urgent password").risk);
    assert.equal(result.scores.aiSemanticContribution, 0);
  }
  ai.recommendation = "Do not send gift-card codes. Contact your manager using a number you already trust.";
  const practical = await analyzeWithScamGuard("gift card", {}, async () => ai);
  assert.equal(practical.recommendation, ai.recommendation);
  const lowAI = { ...ai, classification: "low_risk", socialEngineeringRisk: 0, recommendation: "No action needed." };
  const guarded = await analyzeWithScamGuard("urgent password", {}, async () => lowAI);
  assert.notEqual(guarded.recommendation, lowAI.recommendation);
  console.log("PASS: AI cap, uncertainty discount, deterministic preservation, final cap, and failure/invalid-output fallback.");
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
