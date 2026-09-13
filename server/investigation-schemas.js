const { analysisSchema, validateAnalysis } = require("./ai-analysis-schema");

const decisionSchema = {
  type: "object",
  properties: {
    action: { type: "string", enum: ["analyze_url", "inspect_sender_identity", "finish_investigation"] },
    urlIndex: { type: ["integer", "null"], minimum: 0 },
    organization: { type: ["string", "null"] },
    understanding: { type: "string" },
    reason: { type: "string" }
  },
  required: ["action", "urlIndex", "organization", "understanding", "reason"],
  additionalProperties: false
};

function validateDecision(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== 5 ||
      !["analyze_url", "inspect_sender_identity", "finish_investigation"].includes(value.action) ||
      !(value.urlIndex === null || (Number.isInteger(value.urlIndex) && value.urlIndex >= 0)) ||
      !(value.organization === null || typeof value.organization === "string") ||
      typeof value.understanding !== "string" || typeof value.reason !== "string") throw new Error("Invalid investigator decision.");
  if (value.action === "analyze_url" && value.urlIndex === null) throw new Error("URL analysis requires a URL index.");
  if (value.action !== "analyze_url" && value.urlIndex !== null) throw new Error("Unexpected URL index.");
  return value;
}

module.exports = { decisionSchema, analysisSchema, validateDecision, validateAnalysis };
