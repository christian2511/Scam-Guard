const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { validateAnalysis } = require('./ai-analysis-schema');
const { buildAIInput } = require('./ai-evidence');
const { analyzeWithScamGuard } = require('./analyze-service');

async function main() {
  // Synthetic fixtures only. No Gemini or Groq requests.
  const fixture = {
    phishingLikelihood: 17, confidence: 0.4, classification: 'uncertain',
    scamType: null, claimedOrganization: null, signals: [],
    summary: 'Not enough context for a firm assessment.', recommendation: 'Verify unexpected requests through a trusted contact.'
  };
  validateAnalysis(fixture);
  for (const mutate of [v => { delete v.confidence; }, v => { v.extra = true; }, v => { v.phishingLikelihood = 101; }, v => { v.confidence = -1; }, v => { v.signals = [{ type: 'x', severity: 'critical', explanation: 'x' }]; }]) {
    const invalid = structuredClone(fixture);
    mutate(invalid);
    assert.throws(() => validateAnalysis(invalid));
  }
  const input = buildAIInput({ sender: 'Example <person@example.com>', body: 'urgent password gift cards https://paypal.com@192.0.2.44/login' });
  assert.equal(input.securityChecks.sender.domain, 'example.com');
  assert.equal(input.securityChecks.urlDetails[0].hostname, '192.0.2.44');
  assert.equal(input.securityChecks.urlDetails[0].ipHost, true);
  assert.equal(input.securityChecks.urlDetails[0].hasUserInfo, true);
  assert.ok(!JSON.stringify(input).includes('points'));
  let received;
  const result = await analyzeWithScamGuard(input.message.body, {}, async data => { received = data; return fixture; });
  assert.ok(received.securityChecks);
  assert.equal(result.phishingLikelihood, fixture.phishingLikelihood, 'Evidence cannot add to the AI likelihood');
  assert.equal(result.classification, 'uncertain');
  assert.equal(result.risk, undefined);
  assert.equal(result.scores, undefined);
  const unavailable = await analyzeWithScamGuard(input.message.body, {}, async () => { throw new Error('synthetic failure'); });
  assert.equal(unavailable.aiAvailable, false);
  assert.equal(unavailable.classification, 'analysis_unavailable');
  assert.equal(unavailable.phishingLikelihood, null);
  assert.equal(unavailable.confidence, null);
  assert.ok(unavailable.securityChecks.urlFindings.length);

  const html = fs.readFileSync(path.join(__dirname, '../extension/popup.html'), 'utf8');
  const nodes = Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(match => [match[1], {
    textContent: '', hidden: true, dataset: {}, children: [], addEventListener() {}, replaceChildren() { this.children = []; }, appendChild(node) { this.children.push(node); }
  }]));
  const context = vm.createContext({ document: { getElementById: id => nodes[id], createElement: () => ({ textContent: '' }) } });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../extension/popup.js'), 'utf8'), context);
  context.response = result;
  vm.runInContext('renderAssessment(response)', context);
  assert.equal(nodes.risk.textContent, '17%');
  assert.equal(nodes['risk-level'].textContent, 'UNCERTAIN');
  context.response = unavailable;
  vm.runInContext('renderAssessment(response)', context);
  assert.equal(nodes.risk.hidden, true);
  assert.equal(nodes.risk.textContent, '');
  assert.equal(nodes['risk-level'].textContent, 'ANALYSIS UNAVAILABLE');
  assert.ok(nodes.reasons.children.length > 0);
  console.log('PASS: strict schema, unweighted evidence, AI-only grading, unavailable-without-score, and popup states. No live AI calls.');
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
