<p align="center">
  <img src="assets/banner_1600x400.png" alt="DemonClaw banner" width="100%" />
</p>

# DemonClaw

Purple-team agent runtime in Rust.

DemonClaw is a security-first autonomous agent framework built for purple-team operations, controlled execution, and tamper-evident evidence collection. It combines policy-gated orchestration, sandboxed WASM payloads, semantic routing, and persistent memory into a single Rust-native runtime.

## Release status

**Current state:** release / v0.1.0

Core spec coverage is in place:
- SignalGate semantic routing
- GhostMCP approval boundary
- WASM sandbox + Payload Scanner
- PostgreSQL + pgvector memory
- Evidence Locker hash chain
- AgentLoop orchestration
- interval and basic cron scheduling
- end-to-end acceptance coverage

## What DemonClaw is for

DemonClaw is designed for:
- enterprise vulnerability assessment
- controlled adversarial simulation
- infrastructure validation under explicit guardrails
- evidence-backed defensive and purple-team workflows
- agentic execution with scoped approvals and strong auditability

DemonClaw is **not** positioned as an unsupervised offensive platform. The architecture assumes security boundaries, engagement scoping, and human approval for sensitive actions.

## Architecture

Major subsystems:
- **SignalGate**: semantic routing and intent classification
- **GhostMCP**: authorization boundary and secret injection guardrail
- **Payload Scanner**: pre-execution WASM validation
- **Sandbox**: capability-gated payload execution with fuel/time limits
- **MemoryManager**: PostgreSQL + pgvector retrieval and compaction
- **Evidence Locker**: tamper-evident event chain
- **Scheduler**: interval and cron-driven event injection
- **AgentLoop**: orchestration core for routing, execution, and lifecycle events

See `SPEC.md` for the architecture spec and `CONFIG.md` for runtime configuration.

## Features

- **Envelope ingestion**
  - REPL (stdin) ingestion
  - HTTP ingest endpoint: `POST /ingest`
- **Routing**
  - SignalGate intent classification (`Query`, `Command`, `AttackPayload`)
  - deterministic local fallback for core directives
- **Security controls**
  - engagement context enforcement
  - CIDR/domain allowlists
  - blocked-port and tool-level controls
- **GhostMCP approval boundary** for sensitive actions
- **WASM sandbox** execution for payloads (`wasmtime` + `wasmtime-wasi`)
- **Payload Scanner** for pre-execution import/operator/capability checks
- **Semantic memory** using PostgreSQL + `pgvector`
- **Evidence Locker** with hash-linked audit events
- **Scheduler**
  - interval jobs
  - basic 5-field cron support (`*`, lists, ranges, steps)
- **Acceptance coverage** including end-to-end payload -> evidence flow tests

## Quick start

### 1) Start Postgres with pgvector

```bash
docker compose up -d
```

Default DB is exposed on `localhost:5433`.

### 2) Configure environment

Create a `.env` file with at least:

```bash
DATABASE_URL=postgres://postgres:postgres@localhost:5433/demonclaw
```

Optional but common:

```bash
DEMONCLAW_HTTP_BIND=0.0.0.0:3000
SIGNALGATE_API_KEY=...
EMBEDDING_API_KEY=...
GHOSTMCP_AUTO_APPROVE=0
```

### 3) Run DemonClaw

```bash
cargo run
```

Behavior:
- REPL starts automatically
- HTTP ingest starts automatically
- scheduler starts automatically
- memory optimizer runs in the background when DB is available

### 4) Send a test payload

```bash
curl -s \
  -H 'content-type: application/json' \
  -d '{"content":"payload:test_payload"}' \
  http://localhost:3000/ingest
```

## Testing

```bash
cargo test
```

Notes:
- DB-backed tests skip gracefully if Postgres is unavailable locally.
- end-to-end acceptance coverage includes payload execution through AgentLoop and evidence recording.
- CI runs format, clippy, and tests with a pgvector service container.

## Configuration

See `CONFIG.md` for supported environment variables and runtime behavior.

## Release notes and checklists

- `CHANGELOG.md` - release notes
- `RELEASE_CHECKLIST.md` - release prep and smoke checklist
- `.github/SECURITY.md` - vulnerability reporting policy

## Security

If you discover a vulnerability, do not file a public issue first. See `.github/SECURITY.md`.

## CI/CD

GitHub Actions included:
- `ci.yml` for format, clippy, and test coverage
- `security.yml` for audit and workflow linting

## License

See `LICENSE`.

---

Built by BlueDot IT.
