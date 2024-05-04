const express = require("express");
const bodyParser = require("body-parser");
const https = require("https");
const fs = require("fs");

const app = express();
const port = 443; // HTTPS default port

// Use body-parser middleware
app.use(bodyParser.json());

// Start HTTPS server
const server = https.createServer(
  {
    key: fs.readFileSync("path/to/private.key"),
    cert: fs.readFileSync("path/to/certificate.crt"),
  },
  app
);

server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

// Verification Request endpoint
app.get("/webhooks", (req, res) => {
  let mode = req.query["hub.mode"];
  let token = req.query["hub.verify_token"];
  let challenge = req.query["hub.challenge"];

  if (mode && token) {
    if (mode === "subscribe" && token === "your_verify_token") {
      console.log("Verification successful");
      res.status(200).send(challenge);
    } else {
      console.log("Verification failed");
      res.sendStatus(403);
    }
  } else {
    console.log("Invalid verification request");
    res.sendStatus(400);
  }
});

// Event Notification endpoint
app.post("/webhooks", (req, res) => {
  // Verify request signature
  verifyRequestSignature(req, res, req.rawBody);

  // Handle event notification
  let body = req.body;

  if (body.object === "page") {
    // Process the event
    console.log("Received event notification");
    res.sendStatus(200);
  } else {
    console.log("Invalid event notification");
    res.sendStatus(400);
  }
});

const crypto = require("crypto");

function verifyRequestSignature(req, res, buf) {
  let signature = req.headers["x-hub-signature-256"];

  if (!signature) {
    console.warn("Signature not found");
    throw new Error("Couldn't find 'x-hub-signature-256' in headers");
  }

  let elements = signature.split("=");
  let signatureHash = elements[1];
  let expectedHash = crypto
    .createHmac("sha256", "your_app_secret")
    .update(buf)
    .digest("hex");

  if (signatureHash !== expectedHash) {
    console.warn("Invalid signature");
    throw new Error("Couldn't validate the request signature");
  }
}
