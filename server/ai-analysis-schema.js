const object = properties => ({ type: 'object', properties, required: Object.keys(properties), additionalProperties: false });
const analysisSchema = object({
  phishingLikelihood: { type: 'integer', minimum: 0, maximum: 100 },
  confidence: { type: 'number', minimum: 0, maximum: 1 },
  classification: { type: 'string', enum: ['low_risk', 'suspicious', 'likely_phishing', 'very_likely_phishing', 'uncertain'] },
  scamType: { type: ['string', 'null'] }, claimedOrganization: { type: ['string', 'null'] },
  signals: { type: 'array', items: object({ type: { type: 'string' }, severity: { type: 'string', enum: ['low', 'medium', 'high'] }, explanation: { type: 'string' } }) },
  summary: { type: 'string' }, recommendation: { type: 'string' }
});
function validateNode(value, schema, path = 'analysis') {
  const types = Array.isArray(schema.type) ? schema.type : [schema.type];
  const matches = type => type === 'null' ? value === null
    : type === 'object' ? value !== null && typeof value === 'object' && !Array.isArray(value)
      : type === 'array' ? Array.isArray(value)
        : type === 'integer' ? Number.isInteger(value)
          : type === 'number' ? typeof value === 'number' && Number.isFinite(value) : typeof value === type;
  if (!types.some(matches)) throw new Error(`Invalid type at ${path}.`);
  if (schema.enum && !schema.enum.includes(value)) throw new Error(`Invalid enum at ${path}.`);
  if (typeof value === 'number' && (value < schema.minimum || value > schema.maximum)) throw new Error(`Out of range at ${path}.`);
  if (schema.type === 'object') {
    if (schema.required.some(key => !Object.hasOwn(value, key)) || Object.keys(value).some(key => !Object.hasOwn(schema.properties, key))) throw new Error(`Missing or unexpected fields at ${path}.`);
    for (const [key, child] of Object.entries(schema.properties)) validateNode(value[key], child, `${path}.${key}`);
  }
  if (schema.type === 'array') value.forEach((item, index) => validateNode(item, schema.items, `${path}[${index}]`));
}
function validateAnalysis(value) { validateNode(value, analysisSchema); return value; }
module.exports = { analysisSchema, validateAnalysis };
