# Changelog

## 0.1.0 - 2026-04-20

First stable release.

### Fixed
- memory optimizer maintenance no longer emits invalid REINDEX SQL during runtime
- runtime schema initialization now uses the non-macro SQLx migrator API
- release metadata updated for the 0.1.0 launch

### Validation
- `cargo test --all` passing
- runtime smoke verified with `/healthz` and `POST /ingest`

## 0.1.0-rc1 - 2026-04-13

Release candidate prepared for first tagged release.

Initial release candidate.

### Added
- centralized runtime configuration with env overrides and optional config file
- AgentLoop lifecycle events and structured evidence recording
- payload concurrency control
- interval scheduling and basic cron scheduling
- deterministic local SignalGate fallback for core directives
- end-to-end acceptance test coverage for payload -> evidence flow
- release-facing README refresh

### Improved
- main runtime wiring and subsystem initialization
- integration test behavior in DB-optional local environments
- documentation clarity around release state and feature coverage

### Validation
- `cargo test` passing
- CI configured for fmt, clippy, and test runs with pgvector
