const path = require("node:path");
const { GoogleGenAI } = require("@google/genai");

require("dotenv").config({ path: path.join(__dirname, "..", "..", ".env"), quiet: true });

// Verified against the models returned for the configured Gemini Developer API
// key. This is the current Flash model used for both decisions and assessments.
const GEMINI_MODEL = "gemini-3.8-flash";
const GEMINI_TIMEOUT_MS = 14000;
let client;

function providerError(message, code, cause) {
  const error = new Error(message, cause ? { cause } : undefined);
  error.code = code;
  error.provider = "gemini";
  if (Number.isInteger(cause?.status)) error.status = cause.status;
  return error;
}

function getGeminiClient() {
  if (!client) {
    const apiKey = process.env.GEMINI_API_KEY?.trim();
    if (!apiKey) throw providerError("Gemini is not configured.", "AI_PROVIDER_CONFIG");
    client = new GoogleGenAI({ apiKey });
  }
  return client;
}

async function generateStructured({ systemPrompt, data, schema, signal, maxCompletionTokens = 1200 }) {
  let response;
  try {
    response = await getGeminiClient().interactions.create({
      model: GEMINI_MODEL,
      input: JSON.stringify(data),
      system_instruction: systemPrompt,
      response_format: { type: "text", mime_type: "application/json", schema },
      generation_config: { temperature: 0, max_output_tokens: Math.max(500, maxCompletionTokens) },
      store: false
    }, {
      timeout: GEMINI_TIMEOUT_MS,
      maxRetries: 0,
      fetchOptions: signal ? { signal } : undefined
    });
  } catch (cause) {
    if (cause?.code === "AI_PROVIDER_CONFIG") throw cause;
    const timeout = cause?.name === "AbortError" || /timeout|timed out/i.test(cause?.message || "");
    throw providerError("Gemini request failed.", timeout ? "AI_PROVIDER_TIMEOUT" : "AI_PROVIDER_REQUEST", cause);
  }

  if (response?.status !== "completed" || typeof response.output_text !== "string" || !response.output_text.trim()) {
    throw providerError("Gemini returned an incomplete structured response.", "AI_MALFORMED_RESPONSE");
  }
  try {
    return JSON.parse(response.output_text);
  } catch (cause) {
    throw providerError("Gemini returned malformed JSON.", "AI_MALFORMED_RESPONSE", cause);
  }
}

module.exports = { providerName: "gemini", GEMINI_MODEL, GEMINI_TIMEOUT_MS, generateStructured };
