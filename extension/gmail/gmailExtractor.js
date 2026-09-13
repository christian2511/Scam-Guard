(function (root) {
  "use strict";

  const SELECTORS = Object.freeze({
    main: ["[role='main']", ".AO"],
    message: [".adn[data-message-id]", ".adn[data-legacy-message-id]", ".adn.ads", ".adn", ".h7"],
    body: [".a3s.aiL", ".a3s"],
    subject: ["h2.hP", "[role='main'] h2[data-thread-perm-id]", "[role='main'] h2"],
    sender: [".gD[email]", ".gD[data-hovercard-id]", "[email]", ".go"]
  });

  function first(scope, selectors) {
    for (const selector of selectors) {
      const node = scope?.querySelector?.(selector);
      if (node) return node;
    }
    return null;
  }

  function all(scope, selectors) {
    const seen = new Set();
    const nodes = [];
    for (const selector of selectors) {
      for (const node of scope?.querySelectorAll?.(selector) || []) {
        if (!seen.has(node)) { seen.add(node); nodes.push(node); }
      }
    }
    return nodes;
  }

  function visible(node) {
    if (!node || node.hidden || node.getAttribute?.("aria-hidden") === "true") return false;
    const style = node.ownerDocument?.defaultView?.getComputedStyle?.(node);
    if (style?.display === "none" || style?.visibility === "hidden") return false;
    return !node.getClientRects || node.getClientRects().length > 0;
  }

  function text(value) {
    return String(value || "").replace(/\u00a0/g, " ").replace(/[ \t]+/g, " ").replace(/\s*\n\s*/g, "\n").trim();
  }

  function hash(value) {
    let result = 2166136261;
    for (let index = 0; index < value.length; index += 1) {
      result ^= value.charCodeAt(index);
      result = Math.imul(result, 16777619);
    }
    return (result >>> 0).toString(16).padStart(8, "0");
  }

  function extractCurrentGmailMessage(doc = document, onDiagnostic = () => {}) {
    // Gmail inbox rows do not contain these expanded-body nodes. Starting from
    // visible bodies avoids walking or collecting the inbox message list.
    const main = first(doc, SELECTORS.main) || doc;
    const bodyNode = all(main, SELECTORS.body).filter(node => visible(node) && text(node.innerText || node.textContent)).at(-1);
    if (!bodyNode) { onDiagnostic({ stage: "body_not_found" }); return null; }
    onDiagnostic({ stage: "body_found" });
    const container = bodyNode.closest?.(SELECTORS.message.join(",")) || bodyNode.parentElement;
    if (!container || !visible(container)) { onDiagnostic({ stage: "message_container_not_found" }); return null; }
    onDiagnostic({ stage: "message_container_found" });
    const senderNode = first(container, SELECTORS.sender);
    const subjectNode = first(main, SELECTORS.subject) || first(doc, SELECTORS.subject);
    const subject = text(subjectNode?.innerText || subjectNode?.textContent);
    const senderLabel = text(senderNode?.getAttribute?.("email") || senderNode?.getAttribute?.("data-hovercard-id") || senderNode?.getAttribute?.("title"));
    const senderEmail = senderLabel.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i)?.[0] || "";
    const senderName = text(senderNode?.getAttribute?.("name") || senderNode?.innerText || senderNode?.textContent);
    const bodyText = text(bodyNode.innerText || bodyNode.textContent);
    const links = [...new Set(all(bodyNode, ["a[href]"])
      .map(link => link.href || link.getAttribute?.("href") || "")
      .filter(url => /^https?:\/\//i.test(url)))];
    const nativeId = text(container.getAttribute?.("data-message-id") || container.getAttribute?.("data-legacy-message-id"));
    const fingerprint = hash(JSON.stringify([subject, senderName, senderEmail, bodyText, links]));
    const result = {
      source: "gmail",
      messageId: nativeId || null,
      analysisId: `gmail:${nativeId || "content"}:${fingerprint}`,
      subject,
      senderName,
      senderEmail,
      bodyText,
      links
    };
    Object.defineProperty(result, "statusHost", { value: container, enumerable: false });
    onDiagnostic({
      stage: "extraction_succeeded",
      subjectFound: Boolean(subject), senderNameFound: Boolean(senderName),
      senderEmailFound: Boolean(senderEmail), bodyFound: Boolean(bodyText),
      linkCount: links.length, messageHash: fingerprint
    });
    return result;
  }

  root.ScamGuard = root.ScamGuard || {};
  root.ScamGuard.gmailExtractor = { SELECTORS, extractCurrentGmailMessage, normalizeWhitespace: text, stableHash: hash };
  if (typeof module !== "undefined") module.exports = root.ScamGuard.gmailExtractor;
})(typeof globalThis !== "undefined" ? globalThis : this);
