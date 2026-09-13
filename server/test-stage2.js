const assert = require("node:assert/strict");
const { investigateMessage, MAX_AI_TURNS, MAX_TOOL_CALLS, SECURITY_BOUNDARY, DECISION_PROMPT } = require("./investigation-agent");
const { executeTool } = require("./investigation-tools");
const { getOrCreate } = require("./investigation-cache");

function decision(action, options = {}) {
  return { action, urlIndex: action === "analyze_url" ? (options.urlIndex ?? 0) : null, organization: action === "inspect_sender_identity" ? (options.organization ?? null) : null, understanding: "Reviewed the supplied message as untrusted evidence.", reason: "Gather only relevant evidence." };
}
function assessment(overrides = {}) {
  return { phishingLikelihood: 10, confidence: 0.8, classification: "low_risk", scamType: null, claimedOrganization: null, signals: [], summary: "The supplied text does not show a supported scam pattern.", recommendation: "Verify unexpected requests through a contact you already trust.", ...overrides };
}
function scripted(items, calls) {
  return async request => { calls.push(request); const next = items.shift(); if (next instanceof Error) throw next; return next; };
}
const gmail = (bodyText, extra = {}) => ({ source: "gmail", subject: "", senderName: "", senderEmail: "", bodyText, links: [], initialEvidence: null, ...extra });

async function run(name, request, items, verify) {
  const calls = [];
  const result = await investigateMessage(request, { requestStructured: scripted([...items], calls) });
  verify(result, calls);
  console.log(`PASS ${name}`);
}

async function main() {
  await run("normal finishes with no tools", gmail("Hey, are we still meeting at 4?"), [decision("finish_investigation"), assessment()], (result) => {
    assert.equal(result.aiAvailable, true); assert.equal(result.investigatedEvidence.length, 0); assert.equal(result.limits.toolCalls, 0);
  });
  await run("family impersonation needs no irrelevant URL tool", gmail("Hey Mom, new number. I broke my phone. I need $800 urgently."), [decision("finish_investigation"), assessment({ phishingLikelihood: 82, classification: "very_likely_phishing", scamType: "family_impersonation", signals: [{ type: "new_number_money_request", severity: "high", explanation: "A new-number claim is combined with an urgent money request." }] })], result => {
    assert.equal(result.investigatedEvidence.length, 0); assert.equal(result.scamType, "family_impersonation");
  });
  await run("CEO gift-card path has no URL tool", gmail("I'm in a meeting. Buy five $100 Apple gift cards and send the codes."), [decision("finish_investigation"), assessment({ phishingLikelihood: 85, classification: "very_likely_phishing", scamType: "gift_card_scam" })], result => assert.equal(result.limits.toolCalls, 0));
  await run("Microsoft path analyzes URL then sender", gmail("Your Microsoft account will be deleted. Verify immediately: https://microsoft.com@192.0.2.44/login", { senderName: "Microsoft Security", senderEmail: "notice@example.com", links: ["https://microsoft.com@192.0.2.44/login"] }), [decision("analyze_url"), decision("inspect_sender_identity", { organization: "Microsoft" }), assessment({ phishingLikelihood: 95, confidence: 0.95, classification: "very_likely_phishing", claimedOrganization: "Microsoft" })], result => {
    assert.deepEqual(result.investigatedEvidence.map(item => item.tool), ["analyze_url", "inspect_sender_identity"]);
    assert.equal(result.investigatedEvidence[0].result.ipHost, true); assert.equal(result.investigatedEvidence[0].result.hasUserInfo, true);
    assert.equal(result.investigatedEvidence[1].result.domainConsistent, false);
  });
  await run("educational artifact stays message-level low", gmail("Cybersecurity homework: analyze https://paypal.com@192.0.2.44/login but do not visit it.", { links: ["https://paypal.com@192.0.2.44/login"] }), [decision("analyze_url"), decision("finish_investigation"), assessment({ phishingLikelihood: 8, classification: "low_risk" })], result => {
    assert.equal(result.investigatedEvidence[0].result.ipHost, true); assert.equal(result.classification, "low_risk");
  });
  await run("sender-only identity check", gmail("PayPal account notice", { senderName: "PayPal", senderEmail: "notice@example.com" }), [decision("inspect_sender_identity", { organization: "PayPal" }), decision("finish_investigation"), assessment({ phishingLikelihood: 55, classification: "suspicious", claimedOrganization: "PayPal" })], result => {
    assert.equal(result.investigatedEvidence[0].tool, "inspect_sender_identity"); assert.equal(result.investigatedEvidence[0].result.domainConsistent, false);
  });
  await run("duplicate tool call reuses result", gmail("Review https://paypal.com@192.0.2.44/login", { links: ["https://paypal.com@192.0.2.44/login"] }), [decision("analyze_url"), decision("analyze_url"), assessment()], result => {
    assert.equal(result.investigatedEvidence.length, 2); assert.equal(result.investigatedEvidence[1].reused, true); assert.equal(result.limits.toolCalls, 1);
  });
  await run("agent loop stops at hard limits", gmail("Review two links", { links: ["https://one.example", "https://two.example"] }), [decision("analyze_url", { urlIndex: 0 }), decision("analyze_url", { urlIndex: 1 }), assessment()], (result, calls) => {
    assert.equal(result.limits.toolCalls, MAX_TOOL_CALLS); assert.equal(result.limits.aiTurns, MAX_AI_TURNS); assert.equal(calls.length, MAX_AI_TURNS);
  });
  let attempts = 0;
  await run("429 retries once and preserves state", gmail("Hello"), [Object.assign(new Error("rate"), { status: 429, headers: { "retry-after": "0" } }), decision("finish_investigation"), assessment()], (result, calls) => {
    attempts = calls.length; assert.equal(result.aiAvailable, true);
  });
  assert.equal(attempts, 3);
  await run("structured generation failure retries once", gmail("Microsoft account alert", { senderName: "Microsoft", senderEmail: "notice@example.com" }), [
    Object.assign(new Error("schema mismatch"), { status: 400, error: { error: { code: "json_validate_failed" } } }),
    decision("finish_investigation"),
    assessment({ phishingLikelihood: 45, classification: "suspicious" })
  ], (result, calls) => {
    assert.equal(result.aiAvailable, true); assert.equal(calls.length, 3);
  });
  await run("complete Groq failure preserves evidence", gmail("password immediately https://x.example", { links: ["https://x.example"] }), [Object.assign(new Error("down"), { status: 503 }), Object.assign(new Error("down"), { status: 503 }), Object.assign(new Error("down"), { status: 503 })], result => {
    assert.equal(result.aiAvailable, false); assert.equal(result.classification, "analysis_unavailable"); assert.ok(result.evidence.messageFindings.length); assert.ok(result.evidence.urlDetails.length);
  });
  assert.throws(() => executeTool({ action: "shell", urlIndex: null, organization: null }, { urls: [] }, new Map()), /Unknown/);
  assert.match(SECURITY_BOUNDARY, /UNTRUSTED DATA/); assert.match(DECISION_PROMPT, /exactly/);
  console.log("PASS prompt-injection boundary and unknown-tool rejection");

  let factories = 0;
  const cacheInput = { source: "gmail", bodyText: "cache-test", nonce: Date.now() };
  const factory = async () => { factories += 1; await new Promise(resolve => setTimeout(resolve, 10)); return { aiAvailable: true, value: 1 }; };
  const [first, second] = await Promise.all([getOrCreate(cacheInput, factory), getOrCreate(cacheInput, factory)]);
  const third = await getOrCreate(cacheInput, factory);
  assert.equal(factories, 1); assert.equal(first.cacheStatus, "miss"); assert.equal(second.cacheStatus, "shared"); assert.equal(third.cacheStatus, "hit");
  console.log("PASS completed cache and simultaneous-request deduplication");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
