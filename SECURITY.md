# Security policy

Avron is a security scanner. A vulnerability in the scanner, its API, packaging, or deployment may affect users and third-party systems. Please report security issues privately.

## Supported versions

Security fixes are made against the latest supported release and the current default development branch. Older versions may not receive fixes; upgrade to a supported release when possible.

## Report a vulnerability

Use the repository's **Security** tab and select **Report a vulnerability** (GitHub private vulnerability reporting). Do not disclose vulnerability details in a public issue, discussion, or pull request. If private reporting is not available, contact a repository maintainer privately and ask for a secure reporting channel.

Include, when possible:

- affected version, commit, or deployment method;
- impact and the conditions needed to reproduce it;
- a minimal proof of concept that does not target a third party;
- any suggested mitigation.

Please allow maintainers time to investigate and coordinate a fix before public disclosure. We aim to acknowledge a report within five business days and will share a remediation or disclosure plan as soon as we can. Do not include live credentials, production scan output, or personal data in a report.

## Scope and safe testing

Reports may cover Avron code, its default container configuration, or project automation. Do not test against systems you do not own or have explicit permission to assess. Do not use Avron to access, alter, or disrupt another party's data or services.

Dependency and code scanning alerts are reviewed by maintainers. Public release does not mean every deployment is secure by default; operators must configure secrets, network access, and service exposure safely.
