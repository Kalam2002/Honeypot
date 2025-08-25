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

// Create a write stream for logs
const logStream = fs.createWriteStream(path.join(__dirname, "honeypot.log"), { flags: "a" });

// Log all requests with Morgan
app.use(morgan("combined", { stream: logStream }));

// Fake login page
app.get("/login", (req, res) => {
  res.send(`
    <html>
      <head><title>Login</title></head>
      <body>
        <h2>Sign In</h2>
        <form method="POST" action="/login">
          <label>Username:</label>
          <input type="text" name="username" required /><br><br>
          <label>Password:</label>
          <input type="password" name="password" required /><br><br>
          <button type="submit">Sign In</button>
        </form>
      </body>
    </html>
  `);
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

  // Save log
  fs.appendFileSync("honeypot.log", JSON.stringify(logData, null, 2) + "\n");

  console.log("🚨 Attack logged:", logData);

  // Fake response
  res.send("<h3>Invalid username or password. Try again.</h3>");
});

// Catch all routes (to log scanners / unknown access)
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

