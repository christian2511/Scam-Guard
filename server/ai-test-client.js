const { analyzeSecurityWithAI } = require("./ai-security-analysis");
let lastRequest = 0;

// Development tests only: pace requests and retry explicit rate-limit responses.
async function analyzeForTest(input) {
  const wait = Math.max(0, 30000 - (Date.now() - lastRequest));
  if (wait) await new Promise(resolve => setTimeout(resolve, wait));
  for (let attempt = 0; ; attempt++) {
    lastRequest = Date.now();
    try { return await analyzeSecurityWithAI(input); }
    catch (error) {
      if (error.status !== 429 || attempt >= 2) throw error;
      console.log("Groq rate limit; waiting 30 seconds before retrying this test.");
      await new Promise(resolve => setTimeout(resolve, 30000));
    }
  }
}

module.exports = { analyzeSecurityWithAI: analyzeForTest };
