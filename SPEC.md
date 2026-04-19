# DemonClaw Spec (v0.1)

This document describes DemonClaw as implemented in `main` for the v0.1 release line.

## 1) Purpose

DemonClaw is a Rust-native, security-first agent runtime for purple-team operations. It is designed to:

- ingest “envelopes” (messages) from a REPL or HTTP endpoint
- classify intent (query, command, payload)
- enforce engagement scoping and approvals for sensitive actions
- execute capability-scoped WASM payloads in a sandbox
- persist memory to PostgreSQL + pgvector
- produce tamper-evident evidence via a hash-linked event chain

Non-goal: an unsupervised offensive platform.

## 2) Architecture

Major subsystems (see `src/`):

- **Channels** (`src/channels/mod.rs`): envelope ingestion
  - REPL: stdin line ingestion
  - HTTP: `POST /ingest` (JSON `{ "content": "..." }`)
  - Health: `GET /healthz` (returns `ok`)
  - Assets: `GET /assets/*` served from `./assets`
- **AgentLoop** (`src/loop/mod.rs`): core orchestration loop
- **SignalGate** (`src/signalgate/mod.rs`): intent classification (LLM with deterministic local fallback)
- **SecurityPolicy** (`src/security.rs`): engagement context + network/tool constraints
- **GhostMCP** (`src/ghostmcp/mod.rs`): approval boundary + secret injection guardrail
- **Payload Scanner** (`src/scanner/mod.rs`): pre-execution WASM validation
- **Sandbox** (`src/sandbox/mod.rs`): WASM execution (wasmtime/wasmtime-wasi) with limits
- **MemoryManager** (`src/memory/mod.rs`): pgvector-backed semantic memory
- **EvidenceLocker** (`src/evidence.rs`): tamper-evident audit chain (hash-linked)
- **Scheduler** (`src/scheduler/mod.rs`): interval heartbeat + basic cron-style jobs

## 3) Envelope lifecycle

An envelope is created via `Envelope::new(source, content)` and flows through:

1. **Received**: recorded as evidence (`job.received`)
2. **Classified**: SignalGate returns `Query | Command | AttackPayload | Unknown`
3. **Routed**:
   - **Query**: retrieve context from memory, record completion
   - **Command**: handle internal commands (for example `memory:compact`), record completion
   - **AttackPayload** (`payload:<name>`): enforce policy, require GhostMCP approval, scan payload, sandbox-run, record completion/denial/failure

## 4) Intent classification

Classification uses:

- deterministic local rules for core directives
- otherwise an upstream LLM call (`/chat/completions`) using `SIGNALGATE_*` configuration
- a user-forwarding policy (`drop|hash|passthrough`) for upstream requests

Upstream URL validation supports an allowlist and can forbid non-HTTPS.

## 5) Security model

Key controls:

- optional engagement requirement (`DEMONCLAW_REQUIRE_ENGAGEMENT` + `DEMONCLAW_ENGAGEMENT_ID`)
- private-network-only default policy (`DEMONCLAW_ALLOW_PRIVATE_ONLY=true`)
- CIDR/domain allowlists (`DEMONCLAW_ALLOWED_CIDRS`, `DEMONCLAW_ALLOWED_DOMAINS`)
- blocked ports (`DEMONCLAW_BLOCKED_PORTS`)
- max tool level (`DEMONCLAW_MAX_TOOL_LEVEL=passive|active|intrusive`)

Sensitive actions (notably `execute:*`) require GhostMCP authorization.

## 6) WASM payloads

Payloads live under `payloads/<name>/` and are expected at:

`payloads/<name>/target/wasm32-wasip1/release/<name>.wasm`

Execution steps:

1. load bytes
2. scan imports/capabilities (Payload Scanner)
3. enforce manifest capabilities (sandbox)
4. run with fuel/time limits

(See `payloads/README.md` for building payloads.)

## 7) Persistence

### 7.1 Memory

PostgreSQL + pgvector table `memory_chunks` is created via sqlx migrations in `migrations/`.

### 7.2 Evidence

`evidence_chain` is a hash-linked event chain:

- `prev_hash` links to the last stored event
- `hash` is computed over event fields to make the chain tamper-evident

Chain integrity can be verified by recomputing hashes and link expectations.

## 8) Scheduler

- interval heartbeat injects periodic events (`DEMONCLAW_SCHEDULER_INTERVAL_SECS`)
- basic 5-field cron patterns supported (`*`, lists, ranges, steps)

## 9) Configuration

Configuration is loaded from:

- `demonclaw.json` (or `DEMONCLAW_CONFIG` path), if present
- environment variable overrides (see `CONFIG.md`)

## 10) Release acceptance (minimum)

- `docker compose up -d` brings up pgvector Postgres
- `cargo test --all` passes
- `cargo audit` clean (or explicitly-justified ignores)
- smoke:
  - start runtime, confirm `/healthz` and `POST /ingest`
  - run `payload:test_payload` (with approval configuration)
