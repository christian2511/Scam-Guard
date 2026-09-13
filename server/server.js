const express = require("express");
const cors = require("cors");
require("./groq-client");
const { analyzeWithScamGuard } = require("./analyze-service");
const { normalizeRequest, investigateMessage } = require("./investigation-agent");
const { getOrCreate } = require("./investigation-cache");

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());

app.post("/analyze", async (req, res) => {
  if (typeof req.body?.message !== "string" || !req.body.message.trim()) {
    return res.status(400).json({ error: "Please provide a non-empty message string." });
  }

  const subject = req.body.subject ?? "";
  const sender = req.body.sender ?? "";
  if (typeof subject !== "string" || typeof sender !== "string") {
    return res.status(400).json({ error: "subject and sender must be strings when supplied." });
  }
  if (req.body.message.length + subject.length + sender.length > 20000) {
    return res.status(413).json({ error: "Message and metadata must total at most 20,000 characters." });
  }
  return res.json(await analyzeWithScamGuard(req.body.message, { subject, sender }));
});

app.post("/investigate", async (req, res) => {
  try {
    const request = normalizeRequest(req.body);
    return res.json(await getOrCreate(request, () => investigateMessage(request)));
  } catch (error) {
    if (error instanceof RangeError) return res.status(413).json({ error: error.message });
    if (error instanceof TypeError) return res.status(400).json({ error: error.message });
    throw error;
  }
});

app.use((error, req, res, next) => {
  if (error.type === "entity.parse.failed") return res.status(400).json({ error: "Invalid JSON body." });
  if (error.type === "entity.too.large") return res.status(413).json({ error: "Request body is too large." });
  return res.status(500).json({ error: "Unable to analyze this message. Please try again." });
});

const server = app.listen(port, () => {
  console.log(`ScamGuard server is running at http://localhost:${port}`);
});

server.on("error", (error) => {
  console.error(`Unable to start ScamGuard server: ${error.message}`);
  process.exit(1);
});
