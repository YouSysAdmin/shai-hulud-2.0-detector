#!/bin/bash
# This is a test file that simulates trufflehog activity

echo "Running TruffleHog scan..."
trufflehog --regex --rules=rules.json /home/user/
echo "Scanning for AWS_ACCESS_KEY and GITHUB_TOKEN"
env | grep -E "AWS_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN"

# Collect and exfiltrate environment variables
process.env.AWS_ACCESS_KEY_ID
process.env.GITHUB_TOKEN