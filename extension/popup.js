const analyzeButton = document.getElementById('analyze');
const status = document.getElementById('status');
const analysis = document.getElementById('analysis');
const preview = document.getElementById('preview');
const message = document.getElementById('message');
const labels = {
  low_risk: ['low', '🟢 LOW RISK'], suspicious: ['suspicious', '🟡 SUSPICIOUS'],
  likely_phishing: ['high', '🟠 LIKELY PHISHING'], very_likely_phishing: ['very-high', '🔴 VERY LIKELY PHISHING'],
  uncertain: ['neutral', 'UNCERTAIN'], analysis_unavailable: ['neutral', 'ANALYSIS UNAVAILABLE']
};
function renderAssessment(data) {
  const checks = data?.securityChecks;
  const validFindings = value => Array.isArray(value) && value.every(item => item && typeof item.reason === 'string');
  if (!data || typeof data.aiAvailable !== 'boolean' || !Object.hasOwn(labels, data.classification) ||
      typeof data.summary !== 'string' || typeof data.recommendation !== 'string' ||
      !checks || !validFindings(checks.messageFindings) || !validFindings(checks.urlFindings) ||
      !Array.isArray(data.signals) || !data.signals.every(s => s && typeof s.type === 'string' && typeof s.explanation === 'string' && ['low', 'medium', 'high'].includes(s.severity)) ||
      !(data.claimedOrganization === null || typeof data.claimedOrganization === 'string') ||
      (data.aiAvailable && (data.classification === 'analysis_unavailable' || !Number.isInteger(data.phishingLikelihood) || data.phishingLikelihood < 0 || data.phishingLikelihood > 100 || !Number.isFinite(data.confidence) || data.confidence < 0 || data.confidence > 1)) ||
      (!data.aiAvailable && (data.classification !== 'analysis_unavailable' || data.phishingLikelihood !== null || data.confidence !== null))) {
    throw new Error('The server returned an invalid response. Please try again.');
  }
  const [level, title] = labels[data.classification];
  analysis.dataset.level = level;
  document.getElementById('risk-level').textContent = title;
  const likelihood = document.getElementById('risk');
  likelihood.hidden = !data.aiAvailable;
  likelihood.textContent = data.aiAvailable ? `${data.phishingLikelihood}%` : '';
  document.getElementById('verdict').textContent = data.aiAvailable ? 'AI-estimated phishing likelihood' : 'No phishing grade is available.';
  const reasons = document.getElementById('reasons');
  reasons.replaceChildren();
  const facts = [...checks.urlFindings, ...checks.messageFindings].filter(item => item.reason.trim());
  for (const fact of facts) {
    const item = document.createElement('li');
    item.textContent = fact.reason;
    reasons.appendChild(item);
  }
  document.getElementById('security-empty').hidden = facts.length > 0;
  document.getElementById('ai-details').hidden = !data.aiAvailable;
  document.getElementById('ai-unavailable').hidden = data.aiAvailable;
  const organization = document.getElementById('claimed-organization');
  organization.hidden = !data.aiAvailable || !data.claimedOrganization?.trim();
  organization.textContent = data.aiAvailable && data.claimedOrganization ? `Claimed organization: ${data.claimedOrganization}` : '';
  document.getElementById('semantic-risk').textContent = data.aiAvailable ? `AI confidence: ${Math.round(data.confidence * 100)}%` : '';
  const findings = document.getElementById('ai-findings');
  findings.replaceChildren();
  const signals = data.aiAvailable ? data.signals.filter(s => s.explanation.trim()) : [];
  for (const signal of signals) {
    const item = document.createElement('li');
    item.textContent = `${signal.explanation} (${signal.severity} concern)`;
    findings.appendChild(item);
  }
  document.getElementById('ai-empty').hidden = signals.length > 0;
  document.getElementById('ai-summary').textContent = data.aiAvailable ? data.summary : '';
  document.getElementById('recommendation').textContent = data.recommendation;
  status.textContent = data.aiAvailable ? 'Contextual AI assessment. Technical observations are evidence, not proof.' : 'AI analysis temporarily unavailable.';
  analysis.hidden = false;
}

analyzeButton.addEventListener('click', async () => {
  analyzeButton.disabled = true;
  analysis.hidden = true;
  preview.hidden = true;
  message.textContent = '';
  status.textContent = 'Reading highlighted text…';
  try {
    let selectedText;
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) throw new Error('No tab');
      const results = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: () => window.getSelection().toString() });
      selectedText = results[0]?.result || '';
    } catch {
      status.textContent = 'Unable to read this page. Try highlighting text on a regular webpage; Chrome internal pages restrict extensions.';
      return;
    }
    if (!selectedText.trim()) { status.textContent = 'Please highlight a suspicious message first.'; return; }
    message.textContent = selectedText;
    preview.hidden = false;
    status.textContent = 'Investigating...';
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 45000);
    try {
      const response = await fetch('http://localhost:3000/analyze', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ message: selectedText }), signal: controller.signal
      });
      if (!response.ok) throw new Error(`The server returned an error (${response.status}). Please try again.`);
      let data;
      try { data = await response.json(); } catch (error) {
        if (error.name === 'AbortError') throw error;
        throw new Error('The server returned an invalid response. Please try again.');
      }
      renderAssessment(data);
    } catch (error) {
      status.textContent = error.name === 'AbortError' ? 'The server took too long to respond. Please try again.'
        : error instanceof TypeError ? 'Cannot connect to ScamGuard. Start the backend with npm start, then try again.' : error.message;
    } finally { clearTimeout(timeout); }
  } finally { analyzeButton.disabled = false; }
});
