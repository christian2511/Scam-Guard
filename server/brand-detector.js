const officialDomains = { PayPal: 'paypal.com', Amazon: 'amazon.com', Apple: 'apple.com', Microsoft: 'microsoft.com', Chase: 'chase.com', Google: 'google.com' };
function isOfficialHostname(hostname, domain) {
  const normalized = hostname.toLowerCase().replace(/\.$/, '');
  return normalized === domain || normalized.endsWith(`.${domain}`);
}
function detectBrandImpersonation(message, urls) {
  const prose = message.replace(/https?:\/\/[^\s<>"'`]*/gi, ' ');
  const findings = [];
  for (const [brand, officialDomain] of Object.entries(officialDomains)) {
    if (!new RegExp(`\\b${brand}\\b`, 'i').test(prose)) continue;
    for (const url of urls) {
      try {
        const hostname = new URL(url).hostname;
        if (!isOfficialHostname(hostname, officialDomain)) findings.push({
          type: 'mentioned_brand_domain_mismatch', brand, officialDomain, url, hostname,
          reason: `The text mentions ${brand}; this link's host is outside ${officialDomain}. A mention alone does not establish a sender claim.`,
          limitation: 'Small configured domain list; legitimate regional, partner, and alternate domains may be missing.'
        });
      } catch { /* Parsing failure is recorded by the URL checker. */ }
    }
  }
  return findings;
}
module.exports = { officialDomains, isOfficialHostname, detectBrandImpersonation };
