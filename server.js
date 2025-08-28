const express = require("express");
const fs = require("fs");
const morgan = require("morgan");
const path = require("path");
const bodyParser = require("body-parser");
const geoip = require("geoip-lite");
const { parse } = require("json2csv");

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

// Static files (UI in /public)
app.use(express.static(path.join(__dirname, "public")));

// Create a write stream for raw logs
const logStream = fs.createWriteStream(path.join(__dirname, "honeypot.log"), { flags: "a" });

// Log all requests (raw HTTP logs)
app.use(morgan("combined", { stream: logStream }));

// Path for CSV storage
const csvFile = path.join(__dirname, "honeypot.csv");
// Ensure CSV has headers on first run
if (!fs.existsSync(csvFile)) {
  const headers = "timestamp,username,password,ip,port,browser,country,region,city,path,method\n";
  fs.writeFileSync(csvFile, headers);
}

// Helper to save both JSON log & CSV
function saveLogs(logData) {
  // Save JSON format
  fs.appendFileSync("honeypot.log", JSON.stringify(logData, null, 2) + "\n");

  // Extract structured fields for CSV
  const csvData = {
    timestamp: logData.timestamp,
    username: logData.username || "",
    password: logData.password || "",
    ip: logData.ip,
    port: logData.port,
    browser: logData.browser,
    country: logData.location.country || "",
    region: logData.location.region || "",
    city: logData.location.city || "",
    path: logData.path || "",
    method: logData.method || ""
  };

  // Append CSV row
  const row = Object.values(csvData).map(v => `"${String(v).replace(/"/g, '""')}"`).join(",") + "\n";
  fs.appendFileSync(csvFile, row);
}

// Serve fake login page
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Capture login attempts
app.post("/login", (req, res) => {
  const ip = req.headers["x-forwarded-for"] || req.connection.remoteAddress;
  const geo = geoip.lookup(ip) || {};
  const logData = {
    timestamp: new Date().toISOString(),
    username: req.body.username,
    password: req.body.password,
    ip: ip,
    port: req.connection.remotePort,
    headers: req.headers,
    browser: req.headers["user-agent"],
    location: geo,
    path: "/login",
    method: "POST"
  };

  saveLogs(logData);
  console.log("🚨 Attack logged:", logData);

  res.redirect("/bank");
});

// Fake banking dashboard
app.get("/bank", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "bank.html"));
});

// Catch all unknown routes
app.use((req, res) => {
  const ip = req.headers["x-forwarded-for"] || req.connection.remoteAddress;
  const geo = geoip.lookup(ip) || {};
  const logData = {
    timestamp: new Date().toISOString(),
    path: req.originalUrl,
    method: req.method,
    ip: ip,
    port: req.connection.remotePort,
    headers: req.headers,
    browser: req.headers["user-agent"],
    location: geo
  };

  saveLogs(logData);
  res.status(404).send("<h3>404 Not Found</h3>");
});

// Start server
app.listen(PORT, "0.0.0.0", () => { 
  console.log(`🚀 Honeypot running on http://127.0.0.1:${PORT}`);
  console.log("Logs will be saved in honeypot.log and honeypot.csv");
});

