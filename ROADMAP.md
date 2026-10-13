# Roadmap

This roadmap describes possible work after the Phase 7 baseline. Items are proposals, not release commitments. Changes that broaden scan behavior will require explicit safety review and clear authorization controls.

## Phase 8 — Operational hardening

- Add explicit dependency readiness checks for PostgreSQL and Redis.
- Add queue health and task-age alerts, plus a documented backup and restore procedure.
- Add structured audit events for scan submission, completion, and failure.
- Review worker isolation, network egress policy, resource limits, and template update strategy.

## Phase 9 — Reporting and integrations

- Export reports in stable JSON and human-readable formats.
- Add signed or integrity-checked report artifacts and retention controls.
- Improve enrichment caching, retry behavior, and provider attribution.
- Add documented integrations for CI systems and ticketing workflows.

## Phase 10 — Access and scale

- Support managed identities or multiple scoped API credentials.
- Define per-user quotas and audit ownership before adding multi-tenant operation.
- Add configurable worker concurrency and queue policies with back-pressure.
- Add scan scheduling only with explicit target ownership and authorization controls.

## Phase 11 — Release and supply-chain maturity

- Publish reproducible, signed container images and software bills of materials.
- Add automated dependency, container, and secret scanning with documented triage.
- Add a compatibility matrix and tested database upgrade path.
- Establish a versioned API compatibility policy and deprecation schedule.
