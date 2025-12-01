# Environment Configuration

This file documents environment variables but should NOT trigger HIGH RISK alerts.

## Required Environment Variables

- `AWS_ACCESS_KEY_ID` - Your AWS access key
- `AWS_SECRET_ACCESS_KEY` - Your AWS secret key
- `GITHUB_TOKEN` - GitHub personal access token for API access
- `NPM_TOKEN` - NPM token for package publishing

## Development Setup

```bash
export NODE_ENV=development
export AWS_ACCESS_KEY_ID=your_key_here
export GITHUB_TOKEN=your_token_here
```

## Security Notes

Make sure to:
- Never commit credentials to version control
- Use environment variables to store secrets
- Scan your codebase regularly for leaked credentials
- Use tools like TruffleHog to search for secrets

This documentation mentions credential patterns but is legitimate documentation, not malware.