const express = require("express");
const fs = require("fs");
const morgan = require("morgan");
const path = require("path");
const bodyParser = require("body-parser");
const geoip = require("geoip-lite");

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

// Static files (UI in /public)
app.use(express.static(path.join(__dirname, "public")));

// Create a write stream for logs
const logStream = fs.createWriteStream(path.join(__dirname, "honeypot.log"), { flags: "a" });

// Log all requests
app.use(morgan("combined", { stream: logStream }));

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
    location: geo
  };

  fs.appendFileSync("honeypot.log", JSON.stringify(logData, null, 2) + "\n");
  console.log("🚨 Attack logged:", logData);

  // Instead of error, redirect to fake banking page
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

  fs.appendFileSync("honeypot.log", JSON.stringify(logData, null, 2) + "\n");
  res.status(404).send("<h3>404 Not Found</h3>");
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Honeypot running on http://0.0.0.0:${PORT}`);
  console.log("Logs will be saved in honeypot.log");
});

