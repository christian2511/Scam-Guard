const { extractUrls, inspectUrl } = require('./url-detector');
const { detectBrandImpersonation } = require('./brand-detector');

const rules = {
  urgency: ['urgent', 'immediately', 'act now', 'suspended', 'locked', 'verify now'],
  credentials: ['password', 'login', 'verify your account', 'security code'],
  payments: ['gift card', 'cryptocurrency', 'bitcoin', 'wire transfer'],
  threats: ['account will be closed', 'police', 'arrest', 'penalty']
};
function findIndicators(message, type) {
  return rules[type].flatMap(phrase => {
    const escaped = phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/ /g, '\\s+');
    const plural = ['gift card', 'wire transfer'].includes(phrase) ? 's?' : '';
    const match = new RegExp(`\\b${escaped}${plural}\\b`, 'i').exec(message);
    return match ? [{ type: `${type}_text_match`, evidence: match[0], reason: `Text contains "${match[0]}"; context determines its meaning.` }] : [];
  });
}
const detectUrgency = message => findIndicators(message, 'urgency');
const detectCredentials = message => findIndicators(message, 'credentials');
const detectPayments = message => findIndicators(message, 'payments');
const detectThreats = message => findIndicators(message, 'threats');
function collectDeterministicEvidence(message) {
  const urls = extractUrls(message);
  // URL paths are not message requests. Keep their technical evidence separate.
  const prose = message.replace(/https?:\/\/[^\s<>"'`]*/gi, ' ');
  return {
    urls,
    messageFindings: [...detectUrgency(prose), ...detectCredentials(prose), ...detectPayments(prose), ...detectThreats(prose), ...detectBrandImpersonation(prose, urls)],
    urlFindings: urls.flatMap(inspectUrl)
  };
}
// Evidence only: deliberately no score, verdict, weighting, or recommendation.
module.exports = { collectDeterministicEvidence, detectUrgency, detectCredentials, detectPayments, detectThreats };
