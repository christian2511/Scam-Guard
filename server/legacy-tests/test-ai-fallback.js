const assert = require("node:assert/strict");
const { analyzeWithScamGuard } = require("./analyze-service");
const { analyzeMessage } = require("./detector");
const { getGroqClient } = require("./groq-client");
const { AI_TIMEOUT_MS } = require("./ai-runtime");

async function main() {
  const saved = process.env.GROQ_API_KEY;
  try {
    delete process.env.GROQ_API_KEY;
    assert.throws(getGroqClient, error => error.code === "AI_KEY_MISSING");
  } finally {
    if (saved === undefined) delete process.env.GROQ_API_KEY;
    else process.env.GROQ_API_KEY = saved;
  }
  const message = "urgent password http://192.0.2.1";
  const failures = [
    ["missing key", async () => { throw Object.assign(new Error("private"), { code: "AI_KEY_MISSING" }); }],
    ["network timeout", async () => { throw Object.assign(new Error("private"), { name: "APIConnectionTimeoutError" }); }],
    ["network error", async () => { throw Object.assign(new Error("private"), { name: "APIConnectionError" }); }],
    ["provider error", async () => { throw Object.assign(new Error("private"), { status: 500 }); }],
    ["rate limit", async () => { throw Object.assign(new Error("private"), { status: 429 }); }],
    ["malformed response", async () => ({ socialEngineeringRisk: "bad" })],
    ["empty response", async () => null],
    ["hung request", (input, { signal }) => new Promise(() => { signal.addEventListener("abort", () => { console.log("PASS: underlying hung request received cancellation."); }); })]
  ];
  for (const [name, operation] of failures) {
    const start = Date.now();
    const result = await analyzeWithScamGuard(message, {}, operation);
    assert.equal(result.aiAvailable, false);
    assert.equal(result.aiAnalysis, null);
    assert.equal(result.risk, analyzeMessage(message).risk);
    assert.equal(result.scores.aiSemanticContribution, 0);
    assert.ok(result.securityChecks.urlFindings.length > 0);
    assert.ok(result.securityChecks.messageFindings.length > 0);
    assert.ok(!JSON.stringify(result).includes("private"));
    assert.ok(Date.now() - start < AI_TIMEOUT_MS + 3000);
    console.log(`PASS ${name}: deterministic and URL result retained.`);
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
