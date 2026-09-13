const { getGroqClient, GROQ_MODEL } = require("./groq-client");
const { AI_TIMEOUT_MS } = require("./ai-runtime");

async function requestStructured({ systemPrompt, data, schema, schemaName, signal, maxCompletionTokens = 1200 }) {
  const response = await getGroqClient().chat.completions.create({
    model: GROQ_MODEL,
    messages: [{ role: "system", content: systemPrompt }, { role: "user", content: JSON.stringify(data) }],
    response_format: { type: "json_schema", json_schema: { name: schemaName, strict: true, schema } },
    temperature: 0,
    reasoning_effort: "low",
    max_completion_tokens: maxCompletionTokens,
    tool_choice: "none"
  }, { timeout: AI_TIMEOUT_MS, maxRetries: 0, signal });
  const choice = response.choices?.[0];
  if (choice?.finish_reason !== "stop" || choice.message?.tool_calls?.length) throw new Error("Incomplete structured response.");
  try { return JSON.parse(choice.message.content); }
  catch { throw new Error("Provider returned invalid JSON."); }
}

module.exports = { requestStructured };
