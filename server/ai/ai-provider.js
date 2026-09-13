const geminiProvider = require("./providers/gemini-provider");
const groqProvider = require("./providers/groq-provider");

function statusOf(error) {
  return Number.isInteger(error?.status) ? error.status
    : Number.isInteger(error?.cause?.status) ? error.cause.status : null;
}

function classifyFailure(error) {
  const status = statusOf(error);
  if (error?.code === "AI_PROVIDER_CONFIG" || error?.code === "AI_KEY_MISSING") return "configuration";
  if (error?.code === "AI_MALFORMED_RESPONSE" || /invalid (?:json|type|enum)|missing or unexpected|out of range/i.test(error?.message || "")) return "malformed_response";
  if (error?.code === "AI_PROVIDER_TIMEOUT" || error?.code === "AI_TIMEOUT" || ["AbortError", "APIConnectionTimeoutError"].includes(error?.name)) return "timeout";
  if (status === 429) return "rate_limited";
  if (status >= 500) return "server_error";
  if (status === 401 || status === 403) return "authentication";
  if (["APIConnectionError", "FetchError"].includes(error?.name) || /fetch failed|network/i.test(error?.message || "")) return "temporarily_unavailable";
  return "provider_error";
}

const RECOVERABLE = new Set(["malformed_response", "timeout", "rate_limited", "server_error", "temporarily_unavailable"]);

function safeLog(logger, event) {
  logger(JSON.stringify(event));
}

function createAIProvider({ primary = geminiProvider, fallback = groqProvider, logger = console.warn } = {}) {
  return {
    async generate(options) {
      try {
        const value = await primary.generateStructured(options);
        const validated = options.validate ? options.validate(value) : value;
        safeLog(logger, { event: "ai_provider", provider: primary.providerName, outcome: "succeeded", fallbackUsed: false });
        return { value: validated, providerMetadata: { providerUsed: primary.providerName, fallbackUsed: false, primaryFailure: null } };
      } catch (primaryError) {
        const primaryFailure = classifyFailure(primaryError);
        safeLog(logger, { event: "ai_provider", provider: primary.providerName, outcome: "failed", reason: primaryFailure });
        if (!RECOVERABLE.has(primaryFailure)) {
          primaryError.providerMetadata = { providerUsed: null, fallbackUsed: false, primaryFailure };
          throw primaryError;
        }
        safeLog(logger, { event: "ai_provider", provider: fallback.providerName, outcome: "attempting", fallbackUsed: true });
        try {
          const value = await fallback.generateStructured(options);
          const validated = options.validate ? options.validate(value) : value;
          safeLog(logger, { event: "ai_provider", provider: fallback.providerName, outcome: "succeeded", fallbackUsed: true });
          return { value: validated, providerMetadata: { providerUsed: fallback.providerName, fallbackUsed: true, primaryFailure } };
        } catch (fallbackError) {
          const fallbackFailure = classifyFailure(fallbackError);
          safeLog(logger, { event: "ai_provider", provider: fallback.providerName, outcome: "failed", reason: fallbackFailure, fallbackUsed: true });
          fallbackError.providerMetadata = { providerUsed: null, fallbackUsed: true, primaryFailure, fallbackFailure };
          throw fallbackError;
        }
      }
    }
  };
}

const aiProvider = createAIProvider();

module.exports = { aiProvider, createAIProvider, classifyFailure, RECOVERABLE };
