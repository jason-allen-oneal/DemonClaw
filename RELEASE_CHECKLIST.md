# Release Checklist

## Versioning
- [x] confirm target version/tag
- [x] update `Cargo.toml` version if needed
- [x] review `CHANGELOG.md`

## Code health
- [x] `cargo test`
- [x] `cargo fmt --all -- --check`
- [x] `cargo clippy --all-targets --all-features -- -D warnings`

## Runtime smoke
- [x] start Postgres/pgvector via `docker compose up -d`
- [x] launch DemonClaw with `.env`
- [x] verify `/healthz`
- [x] verify `POST /ingest`
- [x] run `payload:test_payload`
- [x] confirm evidence events recorded
- [x] confirm scheduler interval job fires
- [x] confirm cron job fires

## Release prep
- [x] README updated
- [x] SECURITY policy present
- [x] CI workflows present
- [x] push final commits
- [x] create annotated git tag
- [x] publish GitHub release notes
- [x] set final repo description/homepage/topics if needed
