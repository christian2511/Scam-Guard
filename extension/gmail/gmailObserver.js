(function (root) {
  "use strict";

  // Temporary demo/testing switch. Set false later to show only warnings.
  const SHOW_GMAIL_SAFE_STATUS = true;
  const STATUS_ID = "scamguard-gmail-status";
  const SIGNAL_LABELS = Object.freeze({
    money_request: "Money or payment request",
    credential_or_account_request: "Credential or account request",
    urgency_or_threat: "Urgency or threat",
    identity_or_authority_claim: "Identity or organization claim",
    new_number_behavior: "New-number behavior",
    unusual_request: "Unusual action request",
    suspicious_url_structure: "Suspicious URL structure"
  });
  const RISK_LABELS = Object.freeze({
    low_risk: "🟢 LOW RISK",
    suspicious: "🟡 SUSPICIOUS",
    likely_phishing: "🟠 LIKELY PHISHING",
    very_likely_phishing: "🔴 VERY LIKELY PHISHING",
    uncertain: "⚪ UNCERTAIN",
    analysis_unavailable: "⚪ ANALYSIS UNAVAILABLE"
  });

  function debugEnabled() {
    try { return root.localStorage?.getItem("scamguard.debug") === "1"; }
    catch { return false; }
  }

  function debugLog(stage, details = {}) {
    if (debugEnabled()) console.debug(`[ScamGuard Gmail] ${stage}`, details);
  }

  class GmailMessageObserver {
    constructor({ extract, screen, onResult, onEmpty = () => {}, onDiagnostic = () => {}, observerFactory, debounceMs = 180 }) {
      this.extract = extract;
      this.screen = screen;
      this.onResult = onResult;
      this.onEmpty = onEmpty;
      this.onDiagnostic = onDiagnostic;
      this.observerFactory = observerFactory;
      this.debounceMs = debounceMs;
      this.lastAnalysisId = null;
      this.timer = null;
      this.observer = null;
    }
    process() {
      let message;
      try { message = this.extract(); }
      catch {
        this.onDiagnostic({ stage: "extraction_failed", gmailDetected: true, extractionSucceeded: false, reason: "extractor_error" });
        return false;
      }
      if (!message) {
        if (this.lastAnalysisId !== null) this.onEmpty();
        this.lastAnalysisId = null;
        this.onDiagnostic({ stage: "no_open_message", gmailDetected: true, extractionSucceeded: false });
        return false;
      }
      if (message.analysisId === this.lastAnalysisId) return false;
      this.onDiagnostic({ stage: "message_detected", gmailDetected: true, messageHash: message.analysisId.split(":").at(-1) });
      let screening;
      try { screening = this.screen(message); }
      catch {
        this.onDiagnostic({ stage: "screening_failed", gmailDetected: true, extractionSucceeded: true, messageHash: message.analysisId.split(":").at(-1) });
        return false;
      }
      this.onDiagnostic({
        stage: "screening_complete",
        gmailDetected: true,
        extractionSucceeded: Boolean(message.bodyText),
        messageHash: message.analysisId.split(":").at(-1),
        signals: (screening?.signals || []).map(item => item.category),
        shouldWarn: Boolean(screening?.shouldWarn)
      });
      try { this.onResult(message, screening); }
      catch {
        this.onDiagnostic({ stage: "status_injection_failed", gmailDetected: true, extractionSucceeded: true, messageHash: message.analysisId.split(":").at(-1) });
        return false;
      }
      // Mark the message complete only after screening and warning state update
      // both succeed, so a transient DOM failure can be retried.
      this.lastAnalysisId = message.analysisId;
      return true;
    }
    schedule() {
      // Gmail can mutate continuously while rendering a message. Keeping the
      // first timer guarantees screening runs instead of being postponed by a
      // trailing debounce that is reset forever.
      if (this.timer) return;
      this.timer = setTimeout(() => { this.timer = null; this.process(); }, this.debounceMs);
    }
    start(target) {
      this.observer = this.observerFactory(() => this.schedule());
      this.observer.observe(target, { childList: true, subtree: true, characterData: true });
      this.onDiagnostic({ stage: "observer_started", gmailDetected: true });
      this.process();
    }
    stop() { clearTimeout(this.timer); this.observer?.disconnect(); }
  }

  const state = {
    dismissed: new Set(), card: null, overlay: null, currentAnalysisId: null,
    results: new Map(), inflight: new Map(), controllers: new Map()
  };

  function removeStatus() {
    state.card?.remove();
    if (typeof document !== "undefined") document.getElementById?.(STATUS_ID)?.remove();
    state.card = null;
  }

  function closeOverlay() {
    state.overlay?.remove();
    if (typeof document !== "undefined") document.getElementById?.("scamguard-investigation-overlay")?.remove();
    state.overlay = null;
  }

  function cancelInvestigation(analysisId) {
    state.controllers.get(analysisId)?.abort();
    state.controllers.delete(analysisId);
  }

  function renderTrace(container, data) {
    container.replaceChildren();
    for (const event of data.investigationSteps || []) {
      const row = document.createElement("div");
      row.className = `sg-trace sg-${event.status}`;
      row.textContent = `${event.status === "completed" ? "✓" : event.status === "failed" ? "!" : "→"} ${event.summary}`;
      container.appendChild(row);
    }
  }

  function renderSignals(panel, signals) {
    const section = panel.querySelector("[data-sg-observed]");
    const list = panel.querySelector("[data-sg-signals]");
    list.replaceChildren();
    const categories = [...new Set((signals || []).map(item => item.category))];
    section.hidden = categories.length === 0;
    for (const category of categories) {
      const item = document.createElement("li");
      item.textContent = SIGNAL_LABELS[category] || category.replaceAll("_", " ");
      list.appendChild(item);
    }
  }

  function renderDebug(panel, message, screening) {
    const details = panel.querySelector("[data-sg-debug]");
    details.hidden = !debugEnabled();
    if (details.hidden) return;
    const categories = (screening.signals || []).map(item => item.category);
    panel.querySelector("[data-sg-debug-body]").textContent = [
      "Message detected: yes",
      "Extraction: successful",
      `Signals found: ${categories.length}`,
      `Signals: ${categories.join(", ") || "none"}`,
      `Should warn: ${screening.shouldWarn}`,
      `Message hash: ${message.analysisId.split(":").at(-1)}`
    ].join("\n");
  }

  function renderGmailStatus({ viewState, panel, message, screening, result }) {
    panel.dataset.state = viewState;
    const title = panel.querySelector("[data-sg-title]");
    const description = panel.querySelector("[data-sg-description]");
    const button = panel.querySelector("[data-sg-investigate]");
    const viewButton = panel.querySelector("[data-sg-view-result]");
    const status = panel.querySelector("[data-sg-status]");
    if (viewState === "neutral") {
      title.textContent = "ScamGuard ✓";
      description.textContent = "This email was checked locally. No significant suspicious behavior was detected by the local checks.";
      description.hidden = false;
      button.hidden = true;
      viewButton.hidden = true;
      status.hidden = true;
      status.textContent = "";
      renderSignals(panel, []);
    } else if (viewState === "warning") {
      title.textContent = "⚠ ScamGuard noticed potentially suspicious behavior in this message.";
      description.textContent = "This does not necessarily mean the message is a scam.";
      description.hidden = false;
      button.hidden = false;
      button.disabled = false;
      button.textContent = "Investigate";
      viewButton.hidden = true;
      status.hidden = true;
      status.textContent = "";
      renderSignals(panel, screening.signals);
    } else if (viewState === "investigating") {
      title.textContent = "⚠ ScamGuard noticed potentially suspicious behavior in this message.";
      description.textContent = "This does not necessarily mean the message is a scam.";
      description.hidden = false;
      renderSignals(panel, screening.signals);
      button.hidden = false;
      button.disabled = true;
      button.textContent = "Investigating…";
      viewButton.hidden = true;
      status.hidden = false;
      status.textContent = "Investigation opened in the panel.";
    } else if (viewState === "result") {
      title.textContent = "⚠ ScamGuard noticed potentially suspicious behavior in this message.";
      description.textContent = "This does not necessarily mean the message is a scam.";
      description.hidden = false;
      renderSignals(panel, screening.signals);
      button.hidden = true;
      button.disabled = false;
      viewButton.hidden = false;
      status.hidden = false;
      status.textContent = "Investigation complete —";
    } else if (viewState === "error") {
      title.textContent = "⚠ ScamGuard noticed potentially suspicious behavior in this message.";
      description.textContent = "This does not necessarily mean the message is a scam.";
      description.hidden = false;
      renderSignals(panel, screening.signals);
      button.hidden = false;
      button.disabled = false;
      button.textContent = "Try again";
      viewButton.hidden = true;
      status.hidden = false;
      status.textContent = "Investigation unavailable. The local warning still applies.";
    }
    if (message && screening) renderDebug(panel, message, screening);
  }

  function renderInvestigationOverlay(panel, viewState, screening, result = null) {
    panel.dataset.state = viewState;
    const loading = panel.querySelector("[data-sg-overlay-loading]");
    const resultContent = panel.querySelector("[data-sg-overlay-result]");
    const error = panel.querySelector("[data-sg-overlay-error]");
    loading.hidden = viewState !== "investigating";
    resultContent.hidden = viewState !== "result";
    error.hidden = viewState !== "error";
    if (viewState === "error") {
      error.textContent = "Investigation unavailable. The local warning still applies.";
      return;
    }
    if (viewState !== "result") return;
    panel.querySelector("[data-sg-overlay-risk]").textContent = result.aiAvailable
      ? `${RISK_LABELS[result.classification] || result.classification.replaceAll("_", " ").toUpperCase()} · ${result.phishingLikelihood}%`
      : RISK_LABELS.analysis_unavailable;
    panel.querySelector("[data-sg-overlay-recommendation]").textContent = result.recommendation;
    renderSignals(panel, screening.signals);
    const investigated = panel.querySelector("[data-sg-investigated]");
    investigated.hidden = !(result.investigationSteps || []).length;
    renderTrace(panel.querySelector("[data-sg-trace]"), result);
    const why = panel.querySelector("[data-sg-why]");
    why.hidden = !result.summary?.trim();
    panel.querySelector("[data-sg-summary]").textContent = result.summary || "";
  }

  function openInvestigationOverlay(message, screening, result = null) {
    closeOverlay();
    const panel = document.createElement("aside");
    panel.id = "scamguard-investigation-overlay";
    panel.dataset.scamguardAnalysisId = message.analysisId;
    panel.className = "scamguard-investigation-overlay";
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-label", "ScamGuard Investigation");
    panel.innerHTML = `<button class="sg-overlay-close" data-sg-overlay-close aria-label="Close investigation">×</button><h2>ScamGuard Investigation</h2><p class="sg-overlay-loading" data-sg-overlay-loading>Investigating this message...</p><p class="sg-overlay-error" data-sg-overlay-error hidden></p><div data-sg-overlay-result hidden><div class="sg-overlay-risk" data-sg-overlay-risk></div><section class="sg-overlay-recommendation"><b>Recommended Action</b><p data-sg-overlay-recommendation></p></section><section class="sg-observed" data-sg-observed><b>Observed</b><ul data-sg-signals></ul></section><section class="sg-investigated" data-sg-investigated><b>Investigated</b><div data-sg-trace></div></section><section class="sg-why" data-sg-why><b>Why</b><p data-sg-summary></p></section></div>`;
    panel.querySelector("[data-sg-overlay-close]").addEventListener("click", closeOverlay);
    document.body.appendChild(panel);
    state.overlay = panel;
    renderInvestigationOverlay(panel, result ? "result" : "investigating", screening, result);
    return panel;
  }

  async function investigate(message, screening, panel) {
    const status = panel.querySelector("[data-sg-status]");
    if (state.currentAnalysisId !== message.analysisId || !panel.isConnected) {
      status.hidden = false;
      status.textContent = "This message is no longer open. Open it again to investigate.";
      return;
    }
    const cached = state.results.get(message.analysisId);
    const overlay = openInvestigationOverlay(message, screening, cached || null);
    if (cached) {
      renderGmailStatus({ viewState: "result", panel, message, screening, result: cached });
      return;
    }
    renderGmailStatus({ viewState: "investigating", panel, message, screening });
    let request = state.inflight.get(message.analysisId);
    if (!request) {
      request = (async () => {
        const controller = new AbortController();
        state.controllers.set(message.analysisId, controller);
        const timeout = setTimeout(() => controller.abort(), 45000);
        try {
          const response = await fetch("http://localhost:3000/investigate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              source: "gmail", subject: message.subject, senderName: message.senderName,
              senderEmail: message.senderEmail, bodyText: message.bodyText,
              links: message.links, initialEvidence: screening
            }),
            signal: controller.signal
          });
          if (!response.ok) throw new Error("The investigator could not complete this request.");
          return response.json();
        } finally {
          clearTimeout(timeout);
          state.controllers.delete(message.analysisId);
        }
      })();
      state.inflight.set(message.analysisId, request);
    }
    try {
      const data = await request;
      state.results.set(message.analysisId, data);
      if (state.currentAnalysisId !== message.analysisId) return;
      if (state.overlay === overlay && overlay.isConnected) renderInvestigationOverlay(overlay, "result", screening, data);
      if (state.card === panel && panel.isConnected) renderGmailStatus({ viewState: "result", panel, message, screening, result: data });
    } catch {
      if (state.currentAnalysisId !== message.analysisId) return;
      if (state.overlay === overlay && overlay.isConnected) renderInvestigationOverlay(overlay, "error", screening);
      if (state.card === panel && panel.isConnected) renderGmailStatus({ viewState: "error", panel, message, screening });
    } finally {
      if (state.inflight.get(message.analysisId) === request) state.inflight.delete(message.analysisId);
    }
  }

  function showStatus(message, screening) {
    if (state.currentAnalysisId && state.currentAnalysisId !== message.analysisId) {
      cancelInvestigation(state.currentAnalysisId);
      closeOverlay();
    }
    removeStatus();
    state.currentAnalysisId = message.analysisId;
    if ((!SHOW_GMAIL_SAFE_STATUS && !screening.shouldWarn) || state.dismissed.has(message.analysisId)) return;
    const panel = document.createElement("aside");
    panel.id = STATUS_ID;
    panel.dataset.scamguardAnalysisId = message.analysisId;
    panel.className = "scamguard-gmail-status";
    panel.setAttribute("role", "status");
    panel.innerHTML = `<button class="sg-close" data-sg-dismiss aria-label="Dismiss ScamGuard status">×</button><strong data-sg-title></strong><p data-sg-description></p><div class="sg-observed" data-sg-observed hidden><b>Observed</b><ul data-sg-signals></ul></div><div class="sg-actions"><button data-sg-investigate hidden>Investigate</button><span class="sg-complete" data-sg-status hidden></span><button class="sg-view-result" data-sg-view-result hidden>View Result</button></div><details class="sg-debug" data-sg-debug hidden><summary>ScamGuard Debug</summary><pre data-sg-debug-body></pre></details>`;
    panel.querySelector("[data-sg-dismiss]").addEventListener("click", () => { state.dismissed.add(message.analysisId); removeStatus(); });
    panel.querySelector("[data-sg-investigate]").addEventListener("click", () => investigate(message, screening, panel));
    panel.querySelector("[data-sg-view-result]").addEventListener("click", () => {
      const result = state.results.get(message.analysisId);
      if (state.currentAnalysisId === message.analysisId && result) openInvestigationOverlay(message, screening, result);
    });
    const host = message.statusHost;
    if (host?.prepend) host.prepend(panel);
    else { panel.classList.add("sg-floating"); document.body.appendChild(panel); }
    state.card = panel;
    const cached = state.results.get(message.analysisId);
    const viewState = cached ? "result" : screening.shouldWarn ? "warning" : "neutral";
    renderGmailStatus({ viewState, panel, message, screening, result: cached || null });
    debugLog(`rendering_${viewState}`, { messageHash: message.analysisId.split(":").at(-1), signalCount: screening.signals.length, shouldWarn: screening.shouldWarn });
  }

  root.ScamGuard = root.ScamGuard || {};
  root.ScamGuard.gmailObserver = { SHOW_GMAIL_SAFE_STATUS, STATUS_ID, SIGNAL_LABELS, RISK_LABELS, GmailMessageObserver, renderGmailStatus, renderInvestigationOverlay, openInvestigationOverlay, closeOverlay, showStatus, investigate, state };
  if (typeof module !== "undefined") module.exports = root.ScamGuard.gmailObserver;

  if (typeof document !== "undefined" && typeof MutationObserver !== "undefined" && location.hostname === "mail.google.com") {
    debugLog("content_script_loaded", { host: "mail.google.com" });
    const diagnostic = details => debugLog(details.stage || "diagnostic", details);
    const observer = new GmailMessageObserver({
      extract: () => root.ScamGuard.gmailExtractor.extractCurrentGmailMessage(document, diagnostic),
      screen: root.ScamGuard.localScreening.screenMessage,
      onResult: showStatus,
      onEmpty: () => {
        cancelInvestigation(state.currentAnalysisId);
        state.currentAnalysisId = null;
        closeOverlay();
        removeStatus();
        debugLog("status_removed", { reason: "no_open_message" });
      },
      onDiagnostic: diagnostic,
      observerFactory: callback => new MutationObserver(callback)
    });
    observer.start(document.body);
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
