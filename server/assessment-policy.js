const { validateAnalysis } = require("./ai-analysis-schema");

function classificationFor(likelihood) {
  if (likelihood >= 80) return "very_likely_phishing";
  if (likelihood >= 60) return "likely_phishing";
  if (likelihood >= 30) return "suspicious";
  return "low_risk";
}

function applyAssessmentPolicy(value) {
  const assessment = validateAnalysis(value);
  // The model supplies the holistic likelihood. Application code validates it
  // and makes the public label consistent; deterministic evidence never adds
  // points and benign context can therefore lower message-level risk.
  return { ...assessment, classification: assessment.classification === "uncertain" ? "uncertain" : classificationFor(assessment.phishingLikelihood) };
}

module.exports = { classificationFor, applyAssessmentPolicy };
