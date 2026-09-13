const test = require("node:test");
const assert = require("node:assert/strict");
const { analyzeMessage, getVerdict } = require("./detector");
const { extractUrls, inspectUrl } = require("./url-detector");
const { officialDomains, detectBrandImpersonation } = require("./brand-detector");

test("payment noun plurals match once without matching longer words", () => {
  assert.equal(analyzeMessage("Buy gift cards").risk, 25);
  assert.equal(analyzeMessage("gift card and gift cards").risk, 25);
  assert.equal(analyzeMessage("wire transfers").risk, 25);
  assert.equal(analyzeMessage("gift cardboard").risk, 0);
});

test("all configured brands flag mismatched links with tentative evidence", () => {
  for (const [brand, domain] of Object.entries(officialDomains)) {
    const result = analyzeMessage(`${brand.toUpperCase()}: See https://unrelated.example`);
    assert.equal(result.risk, 35, brand);
    assert.equal(result.verdict, "Suspicious");
    assert.ok(result.reasons[0].includes(domain));
    assert.match(result.reasons[0], /Possible impersonation/);
  }
});

test("official domains and subdomains match, including case and trailing dot", () => {
  for (const [brand, domain] of Object.entries(officialDomains)) {
    for (const host of [domain, `support.${domain}`, domain.toUpperCase(), `${domain}.`]) {
      assert.deepEqual(detectBrandImpersonation(brand, [`https://${host}/`]), []);
    }
  }
});

test("lookalikes, deceptive suffixes, userinfo, and URL paths do not match", () => {
  for (const url of ['https://paypal-account-security.example', 'https://paypal.com.example', 'https://notpaypal.com', 'https://paypal.com@other.example', 'https://other.example/paypal.com']) {
    assert.equal(detectBrandImpersonation('PayPal', [url]).length, 1, url);
  }
});

test("URL-only brand names and partial words are not brand claims", () => {
  assert.deepEqual(detectBrandImpersonation('https://paypal-account-security.example', ['https://paypal-account-security.example']), []);
  assert.deepEqual(detectBrandImpersonation('Pineapple', ['https://other.example']), []);
  assert.deepEqual(detectBrandImpersonation('PayPal', []), []);
  assert.deepEqual(detectBrandImpersonation('PayPal', ['https://']), []);
});

test("mixed links still warn, with one contribution per brand", () => {
  const result = analyzeMessage('PayPal https://paypal.com https://other.example https://another.example');
  assert.equal(result.risk, 35);
  assert.equal(result.reasons.length, 1);
  assert.match(result.reasons[0], /other.example/);
  assert.match(result.reasons[0], /another.example/);
});

test("extracts HTTP(S) URLs, trims prose punctuation and deduplicates", () => {
  assert.deepEqual(extractUrls('See (https://example.com/a). https://example.com/a and HTTP://example.org/path?q=1 ftp://example.net'), ["https://example.com/a", "HTTP://example.org/path?q=1"]);
  assert.deepEqual(extractUrls('https://example.com/a(b) http://[::1]'), ['https://example.com/a(b)', 'http://[::1]']);
  assert.deepEqual(analyzeMessage('No links here').urls, []);
  assert.deepEqual(extractUrls('Broken link https:// here'), ['https://']);
});

test("ordinary URLs add no findings", () => {
  assert.deepEqual(inspectUrl('https://www.example.com/path?q=hello'), []);
});

test("detects all URL indicators including IPv6 and normalized numeric IPs", () => {
  for (const [url, evidence] of [
    ['https://xn--bcher-kva.example', /punycode/],
    [`https://${'a'.repeat(55)}.example.com`, /long hostname/],
    ['https://a.b.c.d.example.com', /hostname levels/],
    ['https://example.com@other.example/path', /@ symbol/],
    ['http://192.0.2.1', /IP-address/],
    ['http://[::1]', /IP-address/],
    ['http://2130706433', /IP-address/],
    ['https://bad..example', /malformed/],
    ['https://example.com:99999', /malformed/],
    ['https:///example.com', /malformed/],
    ['https://example.com/%zz', /malformed/],
    ['https://', /malformed/]
  ]) assert.ok(inspectUrl(url).some(finding => evidence.test(finding.reason)), url);
});

test("URL evidence contributes to risk once per unique URL", () => {
  const result = analyzeMessage('urgent http://192.0.2.1 http://192.0.2.1');
  assert.equal(result.risk, 25);
  assert.deepEqual(result.urls, ['http://192.0.2.1']);
  assert.equal(result.reasons.length, 2);
  assert.equal(analyzeMessage('urgent immediately password login bitcoin police http://192.0.2.1').risk, 100);
});

test("ordinary text has zero risk and no findings", () => {
  const result = analyzeMessage("Lunch tomorrow at noon?");
  assert.equal(result.risk, 0);
  assert.equal(result.verdict, "Low Risk");
  assert.deepEqual(result.reasons, []);
  assert.match(result.recommendation, /does not guarantee safety/);
});

test("each configured phrase is detected with its category weight", () => {
  const groups = [
    [10, ["urgent", "immediately", "act now", "suspended", "locked", "verify now"]],
    [20, ["password", "login", "verify your account", "security code"]],
    [25, ["gift card", "cryptocurrency", "bitcoin", "wire transfer"]],
    [20, ["account will be closed", "police", "arrest", "penalty"]]
  ];
  for (const [points, phrases] of groups) {
    for (const phrase of phrases) {
      const result = analyzeMessage(phrase.toUpperCase());
      assert.equal(result.risk, points, phrase);
      assert.equal(result.reasons.length, 1, phrase);
    }
  }
});

test("distinct findings add up and repeated phrases count once", () => {
  const result = analyzeMessage("Urgent! URGENT! Send your password and bitcoin or face arrest.");
  assert.equal(result.risk, 75);
  assert.equal(result.verdict, "High Risk");
  assert.equal(result.reasons.length, 4);
});

test("score is capped at 100", () => {
  const result = analyzeMessage("urgent immediately password login gift card bitcoin police arrest");
  assert.equal(result.risk, 100);
  assert.equal(result.verdict, "Very High Risk");
});

test("phrase matching handles whitespace and avoids substrings", () => {
  assert.equal(analyzeMessage("ACT\n NOW and security   code").risk, 30);
  assert.equal(analyzeMessage("A surgent word, unlocked door, and policewoman").risk, 0);
});

test("verdict thresholds include every boundary", () => {
  for (const [score, verdict] of [[0, "Low Risk"], [29, "Low Risk"], [30, "Suspicious"], [59, "Suspicious"], [60, "High Risk"], [79, "High Risk"], [80, "Very High Risk"], [100, "Very High Risk"]]) {
    assert.equal(getVerdict(score), verdict);
  }
});
