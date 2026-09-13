const assert = require("node:assert/strict");
const { createAIProvider } = require("./ai/ai-provider");

const provider = (providerName, implementation) => ({ providerName, generateStructured: implementation });
const valid = value => {
  if (!value || value.ok !== true) throw new Error("Invalid type at result.ok.");
  return value;
};

async function scenario(name, primaryImplementation, fallbackImplementation, verify) {
  const events = [];
  const primary = provider("gemini", primaryImplementation);
  const fallback = provider("groq", fallbackImplementation);
  const service = createAIProvider({ primary, fallback, logger: line => events.push(JSON.parse(line)) });
  let result;
  let error;
  try { result = await service.generate({ validate: valid }); } catch (caught) { error = caught; }
  verify({ result, error, events });
  console.log(`PASS provider failover: ${name}`);
}

async function main() {
  await scenario("Gemini success", async () => ({ ok: true }), async () => { throw new Error("must not run"); }, ({ result, events }) => {
    assert.deepEqual(result.providerMetadata, { providerUsed: "gemini", fallbackUsed: false, primaryFailure: null });
    assert.equal(events.length, 1);
  });
  for (const [name, error, reason] of [
    ["Gemini 429", Object.assign(new Error("limited"), { status: 429 }), "rate_limited"],
    ["Gemini timeout", Object.assign(new Error("timed out"), { code: "AI_PROVIDER_TIMEOUT" }), "timeout"],
    ["Gemini 500", Object.assign(new Error("server"), { status: 500 }), "server_error"]
  ]) {
    await scenario(name, async () => { throw error; }, async () => ({ ok: true }), ({ result }) => {
      assert.deepEqual(result.providerMetadata, { providerUsed: "groq", fallbackUsed: true, primaryFailure: reason });
    });
  }
  await scenario("Gemini malformed response", async () => ({ wrong: true }), async () => ({ ok: true }), ({ result }) => {
    assert.equal(result.providerMetadata.providerUsed, "groq");
    assert.equal(result.providerMetadata.primaryFailure, "malformed_response");
  });
  await scenario("both providers unavailable", async () => { throw Object.assign(new Error("down"), { status: 503 }); }, async () => { throw Object.assign(new Error("limited"), { status: 429 }); }, ({ error }) => {
    assert.ok(error); assert.deepEqual(error.providerMetadata, { providerUsed: null, fallbackUsed: true, primaryFailure: "server_error", fallbackFailure: "rate_limited" });
  });
  let fallbackCalls = 0;
  await scenario("configuration errors do not silently fall back", async () => { throw Object.assign(new Error("missing"), { code: "AI_PROVIDER_CONFIG" }); }, async () => { fallbackCalls += 1; return { ok: true }; }, ({ error }) => {
    assert.ok(error); assert.equal(error.providerMetadata.primaryFailure, "configuration");
  });
  assert.equal(fallbackCalls, 0);
}

main().catch(error => { console.error(error); process.exitCode = 1; });
