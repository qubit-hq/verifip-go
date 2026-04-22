# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in any VerifIP SDK, please report it responsibly:

**Email:** security@verifip.com

Please include:
- SDK name and version
- Description of the vulnerability
- Steps to reproduce
- Potential impact

We will acknowledge your report within 48 hours and provide a fix timeline within 5 business days.

## Supported Versions

| SDK | Version | Supported |
|-----|---------|-----------|
| Python | 0.1.x | Yes |
| TypeScript | 0.1.x | Yes |
| Go | 0.1.x | Yes |
| PHP | 0.1.x | Yes |
| Java | 0.1.x | Yes |
| Ruby | 0.1.x | Yes |

## Security Best Practices

- Never hardcode your API key in source code
- Use environment variables: `VERIFIP_API_KEY`
- Rotate API keys periodically via the VerifIP dashboard
- Use the latest SDK version for security patches
