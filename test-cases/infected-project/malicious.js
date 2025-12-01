// Test file with webhook.site reference for content detection
const maliciousPayload = {
  endpoint: "https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7",
  data: "test-payload"
};

function testFunction() {
  console.log("Test webhook endpoint:", maliciousPayload.endpoint);
}

module.exports = { testFunction };