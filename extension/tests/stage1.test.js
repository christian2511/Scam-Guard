const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const { extractCurrentGmailMessage } = require("../gmail/gmailExtractor");
const { screenMessage } = require("../gmail/localScreening");
const { GmailMessageObserver, renderGmailStatus, renderInvestigationOverlay, SHOW_GMAIL_SAFE_STATUS, STATUS_ID } = require("../gmail/gmailObserver");

function visible(extra = {}) {
  return { hidden: false, getAttribute: () => null, getClientRects: () => [1], querySelector: () => null, querySelectorAll: () => [], ...extra };
}

function extractionFixture(bodyText = "Hey, are we still meeting at 4?") {
  const links = [{ href: "https://example.com/path" }, { href: "mailto:a@example.com" }];
  let container;
  const body = visible({ innerText: bodyText, querySelectorAll: selector => selector === "a[href]" ? links : [], closest: () => container });
  const sender = visible({ innerText: "Alex", getAttribute: name => name === "email" ? "alex@example.com" : name === "name" ? "Alex" : null });
  container = visible({
    getAttribute: name => name === "data-message-id" ? "msg-1" : null,
    querySelector: selector => selector === ".a3s.aiL" ? body : selector === ".gD[email]" ? sender : null
  });
  const subject = visible({ innerText: " Meeting   today " });
  const doc = {
    defaultView: { getComputedStyle: () => ({ display: "block", visibility: "visible" }) },
    querySelectorAll: selector => selector === ".a3s.aiL" ? [body] : [],
    querySelector: selector => selector === "h2.hP" ? subject : null
  };
  container.ownerDocument = body.ownerDocument = sender.ownerDocument = subject.ownerDocument = doc;
  return doc;
}

const cases = [
  ["normal", "Hey, are we still meeting at 4?", false],
  ["family impersonation", "Hey Mom, new number. I broke my phone. I need $800 urgently. Can you send it here?", true],
  ["CEO gift card", "I'm in a meeting. Buy five $100 Apple gift cards and send me the codes.", true],
  ["suspicious login", "Your Microsoft account will be deleted today. Verify immediately: https://microsoft.com@192.0.2.44/login", true],
  ["benign payment", "Can you Venmo me $10 for lunch?", false],
  ["educational", "Our cybersecurity lesson today covers gift-card scams and phishing links.", false]
];

const extracted = extractCurrentGmailMessage(extractionFixture());
assert.deepEqual({ source: extracted.source, id: extracted.messageId, subject: extracted.subject, sender: extracted.senderEmail, body: extracted.bodyText, links: extracted.links }, {
  source: "gmail", id: "msg-1", subject: "Meeting today", sender: "alex@example.com", body: "Hey, are we still meeting at 4?", links: ["https://example.com/path"]
});
assert.match(extracted.analysisId, /^gmail:msg-1:[0-9a-f]{8}$/);
assert.ok(extracted.statusHost);
assert.equal(JSON.stringify(extracted).includes("statusHost"), false);
console.log("PASS extraction: current visible message fields normalized.");

let networkCalls = 0;
global.fetch = () => { networkCalls += 1; throw new Error("Stage 1 must not call network"); };
for (const [name, bodyText, expected] of cases) {
  const result = screenMessage({ subject: "", senderName: "", senderEmail: "", bodyText, links: bodyText.match(/https?:\/\/\S+/g) || [] });
  assert.equal(result.shouldWarn, expected, name);
  if (name === "suspicious login") assert.ok(result.signals.some(item => item.category === "credential_or_account_request"));
  console.log(`PASS ${name}: warning=${result.shouldWarn}, signals=${result.signals.map(item => item.category).join(",") || "none"}`);
}
assert.equal(networkCalls, 0);
console.log("PASS privacy: all local screens made zero Gemini/Groq calls.");

let index = 0;
const messages = [{ analysisId: "A" }, { analysisId: "A" }, { analysisId: "B" }];
let screens = 0;
let results = 0;
const observer = new GmailMessageObserver({ extract: () => messages[index++], screen: value => { screens += 1; return value; }, onResult: () => { results += 1; }, observerFactory: () => ({ observe() {}, disconnect() {} }) });
assert.equal(observer.process(), true);
assert.equal(observer.process(), false);
assert.equal(observer.process(), true);
assert.equal(screens, 2);
assert.equal(results, 2);
console.log("PASS SPA behavior: duplicate mutations skipped; message switch screened independently.");

let emptyEvents = 0;
const emptyObserver = new GmailMessageObserver({ extract: () => null, screen: value => value, onResult: () => {}, onEmpty: () => { emptyEvents += 1; }, observerFactory: () => ({ observe() {}, disconnect() {} }) });
emptyObserver.lastAnalysisId = "A";
assert.equal(emptyObserver.process(), false);
assert.equal(emptyEvents, 1);
assert.equal(emptyObserver.lastAnalysisId, null);
console.log("PASS Gmail navigation: leaving a message clears stale warning state.");

const originalSetTimeout = global.setTimeout;
const scheduled = [];
global.setTimeout = callback => { scheduled.push(callback); return 1; };
try {
  const throttled = new GmailMessageObserver({ extract: () => null, screen: value => value, onResult: () => {}, observerFactory: () => ({ observe() {}, disconnect() {} }) });
  throttled.schedule(); throttled.schedule(); throttled.schedule();
  assert.equal(scheduled.length, 1);
  scheduled[0]();
} finally { global.setTimeout = originalSetTimeout; }
console.log("PASS Gmail mutations: continuous mutations cannot reset screening forever.");

let injectionAttempts = 0;
const retryObserver = new GmailMessageObserver({
  extract: () => ({ analysisId: "retry", bodyText: "message" }),
  screen: () => ({ shouldWarn: true, signals: [] }),
  onResult: () => { injectionAttempts += 1; if (injectionAttempts === 1) throw new Error("transient DOM change"); },
  observerFactory: () => ({ observe() {}, disconnect() {} })
});
assert.equal(retryObserver.process(), false);
assert.equal(retryObserver.process(), true);
assert.equal(injectionAttempts, 2);
console.log("PASS warning recovery: transient Gmail DOM injection failures are retried.");

function statusFixture() {
  const nodes = {
    "[data-sg-title]": { textContent: "" }, "[data-sg-description]": { textContent: "" },
    "[data-sg-investigate]": { hidden: false, disabled: false }, "[data-sg-status]": { textContent: "" },
    "[data-sg-view-result]": { hidden: true },
    "[data-sg-observed]": { hidden: true }, "[data-sg-signals]": { children: [], replaceChildren() { this.children = []; }, appendChild(item) { this.children.push(item); } },
    "[data-sg-result-priority]": { hidden: true }, "[data-sg-risk]": { textContent: "" }, "[data-sg-recommendation]": { textContent: "" },
    "[data-sg-investigated]": { hidden: true }, "[data-sg-why]": { hidden: true }, "[data-sg-summary]": { textContent: "" },
    "[data-sg-debug]": { hidden: true }, "[data-sg-debug-body]": { textContent: "" }
  };
  return { panel: { dataset: {}, querySelector: selector => nodes[selector] }, nodes };
}
global.document = { createElement: () => ({ textContent: "" }) };
const neutral = statusFixture();
renderGmailStatus({ viewState: "neutral", panel: neutral.panel, message: { analysisId: "gmail:x:abc12345" }, screening: { shouldWarn: false, signals: [] } });
assert.equal(SHOW_GMAIL_SAFE_STATUS, true);
assert.equal(STATUS_ID, "scamguard-gmail-status");
assert.equal(neutral.panel.dataset.state, "neutral");
assert.equal(neutral.nodes["[data-sg-investigate]"].hidden, true);
assert.match(neutral.nodes["[data-sg-description]"].textContent, /checked locally/);
const warning = statusFixture();
renderGmailStatus({ viewState: "warning", panel: warning.panel, message: { analysisId: "gmail:x:def67890" }, screening: { shouldWarn: true, signals: [{ category: "urgency_or_threat" }, { category: "suspicious_url_structure" }] } });
assert.equal(warning.panel.dataset.state, "warning");
assert.equal(warning.nodes["[data-sg-investigate]"].hidden, false);
assert.deepEqual(warning.nodes["[data-sg-signals]"].children.map(item => item.textContent), ["Urgency or threat", "Suspicious URL structure"]);
const resultCard = statusFixture();
const backendRecommendation = "Do not enter your password. Open the official website directly instead.";
renderGmailStatus({
  viewState: "result", panel: resultCard.panel,
  message: { analysisId: "gmail:x:def67890" }, screening: { shouldWarn: true, signals: [] },
  result: { aiAvailable: true, classification: "very_likely_phishing", phishingLikelihood: 92, recommendation: backendRecommendation, summary: "The request combines account loss threats with a password request.", investigationSteps: [{ step: "analyze_url" }] }
});
assert.equal(resultCard.nodes["[data-sg-investigate]"].hidden, true);
assert.equal(resultCard.nodes["[data-sg-view-result]"].hidden, false);
assert.equal(resultCard.nodes["[data-sg-status]"].textContent, "Investigation complete —");

function overlayFixture() {
  const collection = () => ({ children: [], replaceChildren() { this.children = []; }, appendChild(item) { this.children.push(item); } });
  const nodes = {
    "[data-sg-overlay-loading]": { hidden: false }, "[data-sg-overlay-result]": { hidden: true }, "[data-sg-overlay-error]": { hidden: true, textContent: "" },
    "[data-sg-overlay-risk]": { textContent: "" }, "[data-sg-overlay-recommendation]": { textContent: "" },
    "[data-sg-observed]": { hidden: true }, "[data-sg-signals]": collection(), "[data-sg-investigated]": { hidden: true },
    "[data-sg-trace]": collection(), "[data-sg-why]": { hidden: true }, "[data-sg-summary]": { textContent: "" }
  };
  return { panel: { dataset: {}, querySelector: selector => nodes[selector] }, nodes };
}
const overlay = overlayFixture();
renderInvestigationOverlay(overlay.panel, "result", { signals: [{ category: "credential_or_account_request" }] }, {
  aiAvailable: true, classification: "very_likely_phishing", phishingLikelihood: 92,
  recommendation: backendRecommendation, summary: "The request combines account loss threats with a password request.",
  investigationSteps: [{ step: "analyze_url", status: "completed", summary: "URL destination checked." }]
});
assert.equal(overlay.nodes["[data-sg-overlay-risk]"].textContent, "🔴 VERY LIKELY PHISHING · 92%");
assert.equal(overlay.nodes["[data-sg-overlay-recommendation]"].textContent, backendRecommendation);
assert.equal(overlay.nodes["[data-sg-observed]"].hidden, false);
assert.equal(overlay.nodes["[data-sg-investigated]"].hidden, false);
assert.equal(overlay.nodes["[data-sg-summary]"].textContent, "The request combines account loss threats with a password request.");
assert.equal(networkCalls, 0);
console.log("PASS status + overlay: small card remains compact and result hierarchy renders separately without extra network calls.");

const warningSource = fs.readFileSync(path.join(__dirname, "../gmail/gmailObserver.js"), "utf8");
assert.match(warningSource, /ScamGuard noticed potentially suspicious behavior/);
assert.match(warningSource, /data-sg-investigate/);
assert.match(warningSource, /addEventListener\("click", \(\) => investigate/);
assert.match(warningSource, /STATUS_ID = "scamguard-gmail-status"/);
assert.match(warningSource, /state\.currentAnalysisId !== message\.analysisId/);
assert.match(warningSource, /content_script_loaded/);
assert.match(warningSource, /screening_complete/);
const templates = [...warningSource.matchAll(/panel\.innerHTML = `([^`]+)`/g)].map(match => match[1]);
const overlayTemplate = templates.find(value => value.includes("data-sg-overlay-result")) || "";
assert.ok(overlayTemplate.indexOf("data-sg-overlay-risk") < overlayTemplate.indexOf("data-sg-overlay-recommendation"));
assert.ok(overlayTemplate.indexOf("data-sg-overlay-recommendation") < overlayTemplate.indexOf("data-sg-observed"));
assert.ok(overlayTemplate.indexOf("data-sg-observed") < overlayTemplate.indexOf("data-sg-investigated"));
assert.ok(overlayTemplate.indexOf("data-sg-investigated") < overlayTemplate.indexOf("data-sg-why"));
assert.match(warningSource, /scamguard-investigation-overlay/);
assert.match(warningSource, /state\.results\.get/);
assert.match(warningSource, /state\.inflight\.get/);
assert.equal((warningSource.match(/fetch\(/g) || []).length, 1, "Only the click-driven investigation path may call fetch");
const gmailCss = fs.readFileSync(path.join(__dirname, "../gmail/gmailWarning.css"), "utf8");
assert.match(gmailCss, /\.scamguard-investigation-overlay\s*\{[^}]*position:\s*fixed/i);
assert.match(gmailCss, /\.scamguard-investigation-overlay\s*\{[^}]*top:\s*24px/i);
assert.match(gmailCss, /\.scamguard-investigation-overlay\s*\{[^}]*width:\s*min\(460px/i);
assert.match(gmailCss, /\.scamguard-investigation-overlay\s*\{[^}]*max-height:\s*80vh/i);
assert.match(gmailCss, /\.scamguard-investigation-overlay\s*\{[^}]*overflow-y:\s*auto/i);
console.log("PASS status contract: cautious copy, sanitized diagnostics, dismiss control, and click-only investigation path present.");

const popupSource = fs.readFileSync(path.join(__dirname, "../popup.js"), "utf8");
assert.match(popupSource, /chrome\.scripting\.executeScript/);
assert.match(popupSource, /localhost:3000\/analyze/);
console.log("PASS manual mode contract: highlighted-text extraction and /analyze remain connected.");
