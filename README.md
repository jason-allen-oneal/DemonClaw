<p align="center">
  <img src="assets/banner_1600x400.png" alt="DemonClaw banner" width="100%" />
</p>

# DemonClaw

Purple-team agent runtime in Rust.

DemonClaw is an experimental, security-first agent framework inspired by OpenClaw, built to support purple-team workflows: strict engagement scoping, tool gating/approvals, sandboxed payload execution, and tamper-evident evidence collection.

## Status

This repository is under active development. Interfaces may change.

## Features (current)

- **Envelope ingestion**
  - REPL (stdin) ingestion
  - HTTP ingest endpoint: `POST /ingest`
- **Routing** via SignalGate intent classification (Query/Command/AttackPayload), with local deterministic fallback for core directives
- **Security Policy** gates (engagement context, CIDR/domain allowlists, blocked ports)
- **GhostMCP** approval boundary for sensitive actions
- **WASM sandbox** execution for payloads (wasmtime + wasmtime-wasi)
- **Evidence Locker** (hash-linked, tamper-evident event chain in Postgres)
- **Semantic memory** using Postgres + pgvector (embeddings optional)
- **Scheduler** with interval jobs and basic 5-field cron expression support
- **Acceptance coverage** including end-to-end payload -> evidence flow tests

## Quick start (local)

### 1) Start Postgres (pgvector)

```bash
docker compose up -d
```

Default DB is exposed on `localhost:5433` (see `docker-compose.yml`).

### 2) Configure environment

Copy the example values from `CONFIG.md` into a `.env` file, at minimum:

```bash
DATABASE_URL=postgres://postgres:postgres@localhost:5433/demonclaw
```

### 3) Run

```bash
cargo run
```

- REPL starts automatically (type lines into stdin)
- HTTP ingest starts automatically (bind configured by `DEMONCLAW_HTTP_BIND`)

Example ingest:

```bash
curl -s \
  -H 'content-type: application/json' \
  -d '{"content":"payload:test_payload"}' \
  http://localhost:3000/ingest
```

## Tests

```bash
# With Postgres running and DATABASE_URL set
cargo test
```

Notes:
- DB-backed tests skip gracefully if Postgres is unavailable in the local environment.
- End-to-end acceptance coverage includes payload execution through AgentLoop and evidence recording.

## Configuration

See `CONFIG.md` for all supported environment variables.

## CI/CD

GitHub Actions:
- `.github/workflows/ci.yml` runs fmt, clippy, and tests with a pgvector service container.
- `.github/workflows/security.yml` runs `cargo audit` and a workflow linter (`zizmor`) on a schedule.

## License

See `LICENSE`.

---

Built by BlueDot IT.
