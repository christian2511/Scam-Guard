
const { isIP } = require("node:net");

function extractUrls(message) {
  const candidates = message.match(/https?:\/\/[^\s<>"'`]*/gi) || [];
  return [...new Set(candidates.map((candidate) => {
    // Remove surrounding prose punctuation, retaining balanced URL parentheses.
    let url = candidate.replace(/[.,!?;:]+$/, "");
    for (const [open, close] of [["(", ")"], ["[", "]"], ["{", "}"]]) {
      while (url.endsWith(close) && url.split(close).length > url.split(open).length) {
        url = url.slice(0, -1);
      }
    }
    return url;
  }))];
}

function inspectUrl(url) {
  const findings = [];
  const add = (type, evidence) => findings.push({ type, url, reason: `URL "${url}": ${evidence}` });
  if (url.includes("@")) add("at_symbol", "contains an @ symbol, which can obscure the destination");

  let parsed;
  try {
    // URL parses text only; it does not resolve DNS or make a network request.
    parsed = new URL(url);
  } catch {
    add("malformed_url", "malformed HTTP(S) URL");
    return findings;
  }

  const hostname = parsed.hostname.replace(/\.$/, "");
  const ipHost = hostname.replace(/^\[|\]$/g, "");
  const labels = hostname.split(".");
  if (labels.some((label) => label.startsWith("xn--"))) add("punycode", "punycode hostname label (xn--), which may resemble another domain");
  if (hostname.length > 60) add("long_hostname", `unusually long hostname (${hostname.length} characters; threshold 60)`);
  if (isIP(ipHost)) {
    add("ip_host", "IP-address host instead of a domain name");
  } else if (labels.length >= 6) {
    // Conservative label-count heuristic; not a public-suffix/domain ownership lookup.
    add("many_subdomains", `many hostname levels (${labels.length} labels), suggesting excessive subdomains`);
  }

  const authority = url.slice(url.indexOf("://") + 3).split(/[/?#]/)[0];
  const invalidDomain = !isIP(ipHost) && labels.some((label) =>
    !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
  );
  if (!authority || url.includes("\\") || /%(?![0-9a-f]{2})/i.test(url) || invalidDomain || hostname.length > 253) {
    add("malformed_url", "suspicious malformed URL syntax or hostname");
  }
  return findings;
}

function analyzeUrls(message) {
  const urls = extractUrls(message);
  return { urls, findings: urls.flatMap(inspectUrl) };
}

module.exports = { extractUrls, inspectUrl, analyzeUrls };


