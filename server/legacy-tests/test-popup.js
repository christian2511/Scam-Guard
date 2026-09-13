const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const responses = require("./endpoint-test-results.json");
const script = fs.readFileSync(path.join(__dirname, "../extension/popup.js"), "utf8");
const html = fs.readFileSync(path.join(__dirname, "../extension/popup.html"), "utf8");

async function run(data) {
  let click;
  const makeElement = () => ({ hidden: true, textContent: "", disabled: false, dataset: {}, children: [], addEventListener(event, handler) { click = handler; }, replaceChildren() { this.children = []; }, appendChild(child) { this.children.push(child); } });
  const elements = Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(match => [match[1], makeElement()]));
  vm.runInNewContext(script, {
    document: { getElementById: id => elements[id], createElement: makeElement },
    chrome: { tabs: { query: async () => [{ id: 1 }] }, scripting: { executeScript: async () => [{ result: "Fake selected message" }] } },
    fetch: async () => { assert.equal(elements.status.textContent, "Investigating..."); return { ok: true, json: async () => data }; },
    AbortController, setTimeout, clearTimeout
  });
  await click();
  assert.equal(elements.analysis.hidden, false, elements.status.textContent);
  assert.equal(elements.risk.textContent, `${data.risk}%`);
  assert.equal(elements.verdict.textContent, data.verdict);
  assert.equal(elements.recommendation.textContent, data.recommendation);
  assert.equal(elements.analyze.disabled, false);
  return elements;
}

async function main() {
  for (const name of ["harmless", "phishing", "gift-card", "suspicious-url"]) {
    const data = responses[name];
    const elements = await run(data);
    assert.equal(elements.reasons.children.length, data.securityChecks.urlFindings.length + data.securityChecks.messageFindings.length);
    const visible = Object.entries(data.aiAnalysis).filter(([key, value]) => ["impersonation", "urgency", "credentialRequest", "financialRequest", "personalInformationRequest"].includes(key) && value.detected && value.evidence.trim());
    assert.equal(elements["ai-findings"].children.length, visible.length);
    assert.equal(elements["ai-summary"].textContent, data.aiAnalysis.summary);
    assert.equal(elements["claimed-organization"].hidden, !data.aiAnalysis.claimedOrganization);
    console.log(`PASS popup ${name}: separate technical and AI lists, score, verdict, organization, summary, recommendation.`);
  }
  const unavailable = structuredClone(responses.harmless);
  unavailable.aiStatus = "unavailable";
  unavailable.aiAvailable = false;
  unavailable.aiAnalysis = null;
  const fallback = await run(unavailable);
  assert.equal(fallback["ai-details"].hidden, true);
  assert.equal(fallback["ai-unavailable"].hidden, false);
  assert.equal(fallback.status.textContent, "AI analysis temporarily unavailable.");
  const empty = structuredClone(responses.phishing);
  empty.aiAnalysis.urgency.evidence = "";
  empty.aiAnalysis.credentialRequest.detected = false;
  const filtered = await run(empty);
  assert.ok(filtered["ai-findings"].children.every(item => !item.textContent.startsWith("Creates urgency:") && !item.textContent.startsWith("Requests credentials:")));
  console.log("PASS popup AI-unavailable fallback and empty/false evidence suppression.");
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
