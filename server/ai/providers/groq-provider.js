const { requestStructured } = require("../../groq-structured");

async function generateStructured(options) {
  return requestStructured(options);
}

module.exports = { providerName: "groq", generateStructured };
