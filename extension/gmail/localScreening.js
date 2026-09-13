(function (root) {
  "use strict";

  const patterns = Object.freeze({
    money: /\b(?:send|pay|transfer|buy|purchase|need|wire)\b[^.!?\n]{0,80}(?:\$\s?\d+\b|\bmoney\b|\bgift\s*cards?\b|\bbitcoin\b|\bcrypto(?:currency)?\b|\bwire transfer\b|\bpayment\b|\bcodes?\b)|\b(?:gift\s*cards?|bitcoin|crypto(?:currency)?|wire transfer)\b[^.!?\n]{0,80}\b(?:send|buy|purchase|code)/i,
    credential: /\b(?:send|share|provide|confirm|enter|submit|verify|reset)\b[^.!?\n]{0,70}\b(?:password|login(?: details| credentials)?|account credentials|security code|mfa|verification code)\b|\bverify (?:your )?account\b|\baccount\b[\s\S]{0,100}\b(?:verify|confirm)\b/i,
    urgency: /\b(?:urgent(?:ly)?|immediately|act now|respond now|right away|within \d+ (?:minutes?|hours?)|today|deadline|suspended|locked|deleted|closed|penalty|arrest)\b/i,
    authority: /\b(?:this is (?:your )?(?:ceo|boss|manager)|(?:ceo|boss|manager|fraud department|security team|account security|microsoft|paypal|chase|google|amazon|apple)\b[^.!?\n]{0,50}\b(?:account|alert|department|support|security|request))\b/i,
    newNumber: /\b(?:new (?:phone|number)|lost my phone|broke my phone|texting from (?:a|my) (?:new|different|another) number)\b/i,
    unusualRequest: /\b(?:send (?:me )?(?:the )?(?:gift card )?codes?|keep (?:this|it) (?:secret|confidential)|do not call|don't call|cannot talk|can\'?t talk|i'?m in a meeting)\b/i,
    educational: /\b(?:lesson|training|example|article|homework|awareness|explains?|discusses?|covers?)\b[^.!?\n]{0,80}\b(?:phishing|scam|gift card|password|suspicious link|prompt injection)\b/i
  });

  function inspectUrl(url) {
    const finding = { url, hostname: null, hasAtSymbol: url.includes("@"), hasUserInfo: null, ipHost: null, punycode: null, subdomainCount: null, malformed: false };
    try {
      const parsed = new URL(url);
      finding.hostname = parsed.hostname;
      finding.hasUserInfo = Boolean(parsed.username || parsed.password);
      finding.ipHost = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(parsed.hostname) || /^\[.*\]$/.test(parsed.hostname);
      finding.punycode = parsed.hostname.split(".").some(label => label.startsWith("xn--"));
      finding.subdomainCount = finding.ipHost ? 0 : Math.max(0, parsed.hostname.split(".").length - 2);
    } catch { finding.malformed = true; }
    finding.suspicious = finding.hasUserInfo === true || finding.ipHost === true || finding.punycode === true || finding.malformed || finding.subdomainCount >= 4 || (finding.hostname?.length || 0) > 60;
    return finding;
  }

  function signal(category, evidence, strength = "medium") { return { category, evidence, strength }; }

  function screenMessage(message) {
    const source = [message.subject, message.senderName, message.senderEmail, message.bodyText].filter(Boolean).join("\n");
    const educational = patterns.educational.test(source);
    const urlEvidence = (message.links || []).map(inspectUrl);
    const signals = [];
    const add = (category, regex, strength) => { const match = source.match(regex); if (match) signals.push(signal(category, match[0], strength)); };
    add("money_request", patterns.money, "high");
    add("credential_or_account_request", patterns.credential, "high");
    add("urgency_or_threat", patterns.urgency, "medium");
    add("identity_or_authority_claim", patterns.authority, "medium");
    add("new_number_behavior", patterns.newNumber, "high");
    add("unusual_request", patterns.unusualRequest, "high");
    if (urlEvidence.some(item => item.suspicious)) signals.push(signal("suspicious_url_structure", "One or more link structures need closer review.", "high"));

    const has = category => signals.some(item => item.category === category);
    const combinations = [];
    const warn = (id, categories) => { if (categories.every(has)) combinations.push({ id, categories }); };
    warn("new_contact_money_pressure", ["new_number_behavior", "money_request", "urgency_or_threat"]);
    warn("authority_payment_pressure", ["identity_or_authority_claim", "money_request", "unusual_request"]);
    warn("gift_card_code_request", ["money_request", "unusual_request"]);
    warn("credential_threat", ["credential_or_account_request", "urgency_or_threat"]);
    warn("credential_deceptive_link", ["credential_or_account_request", "suspicious_url_structure"]);
    warn("authority_deceptive_link", ["identity_or_authority_claim", "suspicious_url_structure"]);
    // A clearly educational message suppresses keyword-only combinations, but
    // not a message with direct unusual demands, new-number behavior, or a
    // technically suspicious link plus an actionable credential request.
    const suppress = educational && !has("unusual_request") && !has("new_number_behavior") && !has("credential_or_account_request");
    return { shouldWarn: combinations.length > 0 && !suppress, signals, urlEvidence, combinations, educationalContext: educational };
  }

  root.ScamGuard = root.ScamGuard || {};
  root.ScamGuard.localScreening = { patterns, inspectUrl, screenMessage };
  if (typeof module !== "undefined") module.exports = root.ScamGuard.localScreening;
})(typeof globalThis !== "undefined" ? globalThis : this);
