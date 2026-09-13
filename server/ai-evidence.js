const { isIP } = require('node:net');
const { collectDeterministicEvidence } = require('./detector');
const { inspectUrl } = require('./url-detector');
function buildUrlEvidence(url) {
  const findings = inspectUrl(url);
  let parsed = null;
  try { parsed = new URL(url); } catch { /* Unknown fields stay null. */ }
  const hostname = parsed ? parsed.hostname.replace(/\.$/, '') : null;
  const ipHost = hostname === null ? null : Boolean(isIP(hostname.replace(/^\[|\]$/g, '')));
  return {
    url, hostname, hasAtSymbol: url.includes('@'),
    hasUserInfo: parsed ? Boolean(parsed.username || parsed.password) : null,
    ipHost, punycode: hostname === null ? null : hostname.split('.').some(label => label.startsWith('xn--')),
    hostnameLength: hostname?.length ?? null,
    subdomainCount: hostname === null ? null : ipHost ? 0 : Math.max(0, hostname.split('.').length - 2),
    subdomainCountMethod: 'Label-count estimate assuming a two-label base domain; not public-suffix aware.',
    malformed: findings.some(finding => finding.type === 'malformed_url'), findings
  };
}
function senderEvidence(sender) {
  const address = sender.match(/(?:<|\b)([^\s<>@]+@[^\s<>@]+\.[^\s<>@]+)(?:>|\b)/)?.[1] ?? null;
  return { suppliedSender: sender, address, domain: address ? address.split('@').at(-1).toLowerCase() : null, authenticated: false, limitation: 'Parsed from supplied text only. No SPF, DKIM, DMARC, DNS, or sender verification performed.' };
}
function buildAIInput({ subject = '', sender = '', body = '' } = {}) {
  if (![subject, sender, body].every(value => typeof value === 'string')) throw new TypeError('Invalid message metadata.');
  const { urls, messageFindings, urlFindings } = collectDeterministicEvidence([subject, sender, body].join('\n'));
  const securityChecks = { messageFindings, urlFindings, urlDetails: urls.map(buildUrlEvidence), sender: senderEvidence(sender) };
  return { message: { subject, sender, body }, urls, securityChecks };
}
module.exports = { buildAIInput, buildUrlEvidence, senderEvidence };
