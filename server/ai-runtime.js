// Covers one normal request plus a short rate-limit retry without making the
// extension wait indefinitely.
// Allows a bounded Gemini attempt plus a Groq fallback while still preventing
// a provider outage from leaving an extension request open indefinitely.
const AI_TIMEOUT_MS = 35000;

async function withAIDeadline(operation, timeoutMs = AI_TIMEOUT_MS) {
  const controller = new AbortController();
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(() => operation(controller.signal)),
      new Promise((resolve, reject) => {
        timer = setTimeout(() => {
          const error = new Error("AI deadline exceeded.");
          error.code = "AI_TIMEOUT";
          reject(error);
          controller.abort();
        }, timeoutMs);
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function logAIFailure(error, elapsedMs) {
  const status = Number.isInteger(error?.status) ? error.status : null;
  const category = error?.code === "AI_KEY_MISSING" ? "missing_key"
    : error?.code === "AI_TIMEOUT" || ["AbortError", "APIConnectionTimeoutError"].includes(error?.name) ? "timeout"
      : status === 429 ? "rate_limit"
        : status === 401 || status === 403 ? "authentication"
          : status ? "provider_error"
            : error?.name === "APIConnectionError" ? "network_error" : "invalid_response_or_analysis_error";
  // Only allowlisted diagnostic data; never log messages, SDK objects, headers,
  // API keys, request bodies, or provider response text.
  const retryAfter = error?.headers?.get?.("retry-after") ?? error?.headers?.["retry-after"] ?? null;
  console.warn(JSON.stringify({ event: "ai_analysis_unavailable", category, status, elapsedMs, retryAfter }));
}

module.exports = { AI_TIMEOUT_MS, withAIDeadline, logAIFailure };
