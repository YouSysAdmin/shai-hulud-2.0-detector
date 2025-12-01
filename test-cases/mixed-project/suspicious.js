// This file contains some suspicious patterns but may not be malicious
const config = {
  webhookUrl: "https://webhook.site/some-other-endpoint",
  logLevel: "debug"
};

function sendData(payload) {
  // This might be legitimate webhook usage
  console.log("Sending to webhook:", config.webhookUrl);
}