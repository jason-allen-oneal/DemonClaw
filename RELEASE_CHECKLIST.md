# Release Checklist

## Versioning
- [ ] confirm target version/tag
- [ ] update `Cargo.toml` version if needed
- [ ] review `CHANGELOG.md`

## Code health
- [x] `cargo test`
- [x] `cargo fmt --all -- --check`
- [x] `cargo clippy --all-targets --all-features -- -D warnings`

## Runtime smoke
- [ ] start Postgres/pgvector via `docker compose up -d`
- [ ] launch DemonClaw with `.env`
- [ ] verify `/healthz`
- [ ] verify `POST /ingest`
- [ ] run `payload:test_payload`
- [ ] confirm evidence events recorded
- [ ] confirm scheduler interval job fires
- [ ] confirm cron job fires

## Release prep
- [x] README updated
- [x] SECURITY policy present
- [x] CI workflows present
- [ ] push final commits
- [ ] create annotated git tag
- [ ] publish GitHub release notes
- [ ] set final repo description/homepage/topics if needed
