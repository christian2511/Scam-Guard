const { buildUrlEvidence } = require("./ai-evidence");
const { officialDomains, isOfficialHostname } = require("./brand-detector");

const ALLOWED_TOOLS = Object.freeze(["analyze_url", "inspect_sender_identity", "finish_investigation"]);

function parseSender(senderEmail, senderName) {
  const supplied = [senderName, senderEmail].filter(Boolean).join(" ");
  const address = supplied.match(/(?:<|\b)([^\s<>@]+@[^\s<>@]+\.[^\s<>@]+)(?:>|\b)/)?.[1] || null;
  return { visibleSender: supplied || null, senderEmail: address, senderDomain: address ? address.split("@").at(-1).toLowerCase() : null };
}

function inspectSenderIdentity(state, organization) {
  const sender = parseSender(state.message.senderEmail, state.message.senderName);
  const mentioned = organization && Object.hasOwn(officialDomains, organization) &&
    new RegExp(`\\b${organization.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i").test([state.message.subject, state.message.senderName, state.message.bodyText].join("\n"));
  const claimedOrganization = mentioned ? organization : null;
  const knownOfficialDomains = claimedOrganization ? [officialDomains[claimedOrganization]] : [];
  const domainConsistent = sender.senderDomain && claimedOrganization
    ? isOfficialHostname(sender.senderDomain, officialDomains[claimedOrganization]) : null;
  return {
    ...sender,
    claimedOrganization,
    knownOfficialDomains,
    domainConsistent,
    metadataAvailable: Boolean(sender.visibleSender),
    authenticationPerformed: false,
    limitation: "Visible sender text only; no SPF, DKIM, DMARC, DNS, or authentication check was performed."
  };
}

function toolKey(action, decision) {
  return action === "analyze_url" ? `${action}:${decision.urlIndex}` : action;
}

function executeTool(decision, state, cache) {
  if (!ALLOWED_TOOLS.includes(decision.action)) throw new Error("Unknown investigation tool.");
  if (decision.action === "finish_investigation") return { result: { ready: true }, reused: false, key: decision.action };
  const key = toolKey(decision.action, decision);
  if (cache.has(key)) return { result: cache.get(key), reused: true, key };
  let result;
  if (decision.action === "analyze_url") {
    if (!Number.isInteger(decision.urlIndex) || !state.urls[decision.urlIndex]) throw new Error("Invalid URL selection.");
    result = buildUrlEvidence(state.urls[decision.urlIndex]);
  } else {
    if (decision.organization !== null && !Object.hasOwn(officialDomains, decision.organization)) throw new Error("Unknown organization selection.");
    result = inspectSenderIdentity(state, decision.organization);
  }
  cache.set(key, result);
  return { result, reused: false, key };
}

module.exports = { ALLOWED_TOOLS, parseSender, inspectSenderIdentity, executeTool };
