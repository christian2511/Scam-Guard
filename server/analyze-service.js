const { analyzeSecurityWithAI } = require('./ai-security-analysis');
const { validateAnalysis } = require('./ai-analysis-schema');
const { buildAIInput } = require('./ai-evidence');
const { withAIDeadline, logAIFailure } = require('./ai-runtime');

function retryDelayMs(error) {
  if (error?.status !== 429) return null;
  const raw = error?.headers?.get?.('retry-after') ?? error?.headers?.['retry-after'];
  const seconds = Number(raw);
  // Retry only when Groq says the request can recover quickly. Longer limits
  // fall back immediately so the popup stays responsive and the next user
  // request can try again after the provider window resets.
  if (Number.isFinite(seconds)) return seconds <= 4 ? Math.max(250, seconds * 1000) : null;
  return 1000;
}

async function requestAI(analyzeAI, input, signal) {
  try {
    return await analyzeAI(input, { signal });
  } catch (error) {
    const delay = retryDelayMs(error);
    if (delay === null || signal.aborted) throw error;
    console.warn(JSON.stringify({ event: 'ai_rate_limit_retry', delayMs: delay }));
    await new Promise((resolve, reject) => {
      const timer = setTimeout(resolve, delay);
      signal.addEventListener('abort', () => { clearTimeout(timer); reject(Object.assign(new Error('AI retry cancelled.'), { code: 'AI_TIMEOUT' })); }, { once: true });
    });
    return analyzeAI(input, { signal });
  }
}
async function analyzeWithScamGuard(body, { subject = '', sender = '' } = {}, analyzeAI = analyzeSecurityWithAI) {
  // Evidence survives AI errors. There are no points or final-score arithmetic.
  const input = buildAIInput({ subject, sender, body });
  let ai = null;
  let providerMetadata = { providerUsed: null, fallbackUsed: false, primaryFailure: null };
  const started = Date.now();
  try {
    const generated = await withAIDeadline(signal => requestAI(analyzeAI, input, signal));
    ai = generated?.analysis ?? generated;
    providerMetadata = generated?.providerMetadata ?? providerMetadata;
    validateAnalysis(ai);
  } catch (error) {
    ai = null;
    providerMetadata = error?.providerMetadata ?? providerMetadata;
    logAIFailure(error, Date.now() - started);
  }
  return {
    phishingLikelihood: ai?.phishingLikelihood ?? null,
    confidence: ai?.confidence ?? null,
    classification: ai?.classification ?? 'analysis_unavailable',
    scamType: ai?.scamType ?? null,
    claimedOrganization: ai?.claimedOrganization ?? null,
    signals: ai?.signals ?? [],
    summary: ai?.summary ?? 'AI analysis temporarily unavailable. Security evidence is shown without a phishing assessment.',
    recommendation: ai?.recommendation ?? 'If the message asks you to act, verify it through a contact or app you already trust before sharing information or sending money.',
    securityChecks: input.securityChecks,
    urls: input.urls,
    aiAvailable: ai !== null,
    aiAnalysis: ai,
    ...providerMetadata
  };
}
module.exports = { analyzeWithScamGuard };
