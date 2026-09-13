const path = require("node:path");
const Groq = require("groq-sdk");

require("dotenv").config({ path: path.join(__dirname, ".env"), quiet: true });

const GROQ_MODEL = "openai/gpt-oss-20b";
let client;

// Lazily initialize so the existing rules server works without an AI key.
// Creating a client does not make a network request.
function getGroqClient() {
  if (!client) {
    const apiKey = process.env.GROQ_API_KEY?.trim();
    if (!apiKey) {
      const error = new Error("Set GROQ_API_KEY in server/.env before using Groq.");
      error.code = "AI_KEY_MISSING";
      throw error;
    }
    client = new Groq({ apiKey });
  }
  return client;
}

module.exports = { getGroqClient, GROQ_MODEL };
