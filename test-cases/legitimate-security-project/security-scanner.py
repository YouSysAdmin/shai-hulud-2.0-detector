#!/usr/bin/env python3
"""
Legitimate security scanner - should be MEDIUM risk at most
This is a proper security tool, not malware
"""

import os
import subprocess
import json

def scan_for_secrets():
    """Legitimate security function that scans for secrets"""
    print("Running legitimate security scan...")

    # This should be MEDIUM risk, not HIGH risk
    # Legitimate security tools may reference these patterns
    secret_patterns = [
        'AWS_ACCESS_KEY',
        'GITHUB_TOKEN',
        'NPM_TOKEN',
        'SLACK_TOKEN'
    ]

    results = []

    # Scan environment variables (legitimate security practice)
    for key, value in os.environ.items():
        for pattern in secret_patterns:
            if pattern in key:
                results.append({
                    'type': 'env_var',
                    'key': key,
                    'risk': 'potential_secret'
                })

    return results

def run_trufflehog():
    """Run TruffleHog security scanner - this is legitimate use"""
    try:
        # This is legitimate security scanning
        result = subprocess.run([
            'trufflehog',
            '--regex',
            '--entropy=False',
            '.'
        ], capture_output=True, text=True)

        return result.stdout
    except FileNotFoundError:
        print("TruffleHog not installed")
        return None

def main():
    print("Starting security audit...")

    # Collect security findings
    findings = scan_for_secrets()

    # Run additional security tools
    trufflehog_results = run_trufflehog()

    # Generate report
    report = {
        'timestamp': '2025-01-16',
        'findings': findings,
        'trufflehog_output': trufflehog_results
    }

    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()