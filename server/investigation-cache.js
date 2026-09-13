const { createHash } = require("node:crypto");

const TTL_MS = 10 * 60 * 1000;
const MAX_ENTRIES = 200;
const complete = new Map();
const inflight = new Map();

function investigationKey(input) {
  return createHash("sha256").update(JSON.stringify(input)).digest("hex");
}

function trim() {
  while (complete.size > MAX_ENTRIES) complete.delete(complete.keys().next().value);
}

async function getOrCreate(input, factory) {
  const key = investigationKey(input);
  const cached = complete.get(key);
  if (cached && cached.expiresAt > Date.now()) return { ...cached.result, cacheStatus: "hit" };
  if (cached) complete.delete(key);
  if (inflight.has(key)) return { ...(await inflight.get(key)), cacheStatus: "shared" };
  const promise = factory().then(result => {
    if (result.aiAvailable) { complete.set(key, { result, expiresAt: Date.now() + TTL_MS }); trim(); }
    return result;
  }).finally(() => inflight.delete(key));
  inflight.set(key, promise);
  return { ...(await promise), cacheStatus: "miss" };
}

module.exports = { TTL_MS, MAX_ENTRIES, investigationKey, getOrCreate };
