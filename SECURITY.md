# Security Policy

## Supported Versions

ATTACK-Navi is currently maintained as a moving `main` branch project.

| Deployment or Version | Supported |
| --- | --- |
| Latest `main` branch | Yes |
| Latest GitHub Pages deployment | Yes |
| Older historical commits | Best effort only |
| Custom self-hosted forks | Configuration dependent |

## Reporting a Vulnerability

Please report security issues privately and do not open a public issue first.

Preferred approach:

1. Use GitHub's private vulnerability reporting flow for this repository if it is available.
2. If that is not available, contact the maintainer privately through GitHub before public disclosure.
3. Include reproduction steps, affected configuration, impact, and any suggested mitigation.

The goal is coordinated disclosure with enough time to validate the issue and publish a fix or mitigation guidance first.

## Security Scope

ATTACK-Navi is primarily a client-side Angular application with optional integration points and an optional backend proxy. The most important security areas are:

- third-party dependency vulnerabilities
- unsafe handling of integration secrets
- XSS or unsafe rendering from external data sources
- insecure OpenCTI or MISP deployment patterns
- export or file-generation features that process untrusted input

## Recommended Deployment Posture

- Treat the GitHub Pages build as the safest default for the core matrix experience.
- Use the optional `server/` proxy when you do not want browser clients holding integration tokens directly.
- Do not commit API keys, bearer tokens, or environment files with secrets.
- Review integration settings before connecting ATTACK-Navi to production MISP or OpenCTI instances.

## Current Controls

- GitHub Actions security workflows for CodeQL, OSV-Scanner, and dependency review
- optional backend proxy support for integrations that should not expose secrets to browser clients
- documentation for workflows, architecture, and data-source trust boundaries
- lockfile-based dependency management with regular updates

## Disclosure Expectations

Please allow reasonable time to investigate and remediate reported issues before public disclosure. If a report cannot be reproduced or falls outside the supported scope, maintainers may close it with an explanation.
