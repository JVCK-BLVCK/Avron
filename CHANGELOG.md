# Changelog

All notable changes to Avron are documented here. This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses Semantic Versioning for published releases.

## [Unreleased]

### Added

- MCP tools for scan history, CVE/EPSS analysis, report generation, and scan comparison.
- Project installation, configuration, architecture, API/MCP, and troubleshooting guides.
- Contribution, conduct, and vulnerability disclosure policies.
- Cross-platform CI, CodeQL workflow, Dependabot configuration, and GitHub issue/PR templates.
- Coverage settings and an extended roadmap for post-Phase-7 work.

### Changed

- Route MCP scan requests through the same Celery queue used by the REST API.
- Make the Nuclei scan timeout and Prometheus endpoint configurable.
- Use Avron branding and remove unused/duplicate development dependencies.

### Security

- Preserve target validation and worker-side DNS revalidation for REST and MCP submissions.
- Keep Compose service ports bound to loopback for local development.
