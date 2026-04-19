# DemonClaw Configuration

DemonClaw uses environment variables for configuration. All settings can be provided via `.env` file or exported directly.

## Core System

| Variable | Default | Description |
|----------|---------|-------------|
| `DEMONCLAW_HTTP_BIND` | `0.0.0.0:3000` | HTTP ingest server bind address |
| `DEMONCLAW_INGEST_AUTH_ENABLED` | `false` | Enable auth for `/ingest` endpoint |
| `DEMONCLAW_INGEST_AUTH_HEADER` | `x-demonclaw-token` | Header name for ingest auth token |
| `DEMONCLAW_INGEST_TOKEN_ENV` | `DEMONCLAW_TOKEN` | Env var containing ingest token |
| `DEMONCLAW_MAX_BODY_BYTES` | `1000000` | Max HTTP request body size (1MB) |
| `DATABASE_URL` | `postgres://localhost/demonclaw` | PostgreSQL connection string |

## Security Policy

| Variable | Default | Description |
|----------|---------|-------------|
| `DEMONCLAW_REQUIRE_ENGAGEMENT` | `false` | Require engagement context for operations |
| `DEMONCLAW_ENGAGEMENT_ID` | - | Current engagement identifier |
| `DEMONCLAW_ALLOW_PRIVATE_ONLY` | `true` | Only allow private IP addresses (RFC1918) |
| `DEMONCLAW_ALLOWED_CIDRS` | - | Comma-separated allowed CIDR blocks |
| `DEMONCLAW_BLOCKED_PORTS` | `22,2375,2376,3389` | Comma-separated blocked ports |
| `DEMONCLAW_ALLOWED_DOMAINS` | - | Comma-separated allowed domains |
| `DEMONCLAW_MAX_TOOL_LEVEL` | `intrusive` | Max tool level: `passive`, `active`, `intrusive` |

## SignalGate (Semantic Routing)

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGNALGATE_BASE_URL` | `https://api.openai.com/v1` | LLM API base URL |
| `SIGNALGATE_API_KEY` | - | LLM API key |
| `SIGNALGATE_MODEL` | `gpt-4o` | Model for intent classification |
| `SIGNALGATE_UPSTREAM_ALLOW_HTTP` | `false` | Allow non-HTTPS upstreams |
| `SIGNALGATE_UPSTREAM_ALLOWLIST` | - | Format: `provider1=url1,url2;provider2=url3` |
| `SIGNALGATE_USER_FORWARD_MODE` | `hash` | User forwarding: `drop`, `hash`, `passthrough` |
| `SIGNALGATE_USER_SALT` | - | Salt for user hash forwarding |

## Embeddings (Semantic Memory)

| Variable | Default | Description |
|----------|---------|-------------|
| `EMBEDDING_BASE_URL` | `https://api.openai.com/v1` | Embedding API base URL |
| `EMBEDDING_API_KEY` | - | Embedding API key (required for embeddings) |
| `EMBEDDING_MODEL` | `text-embedding-3-small` | Embedding model |
| `EMBEDDING_DIMENSION` | `1536` | Embedding vector dimension |

## WASM Sandbox Limits

| Variable | Default | Description |
|----------|---------|-------------|
| `DEMONCLAW_SANDBOX_FUEL_LIMIT` | `10000000` | Max instructions per payload (10M) |
| `DEMONCLAW_SANDBOX_TIMEOUT_SECS` | `30` | Max execution time per payload (30s) |

## GhostMCP (Authorization Boundary)

| Variable | Default | Description |
|----------|---------|-------------|
| `GHOSTMCP_AUTO_APPROVE` | `false` | Auto-approve actions (dev only) |
| `GHOSTMCP_APPROVAL_TOKEN` | - | Token for automated approval |
| `GHOSTMCP_HUMAN_TOKEN` | - | Human-provided approval token |
| `GHOSTMCP_ALLOWED_ACTIONS` | - | Comma-separated allowlisted actions |
| `DC_SECRET_*` | - | Secret store (e.g., `DC_SECRET_API_KEY`) |

## Active Defense (Intrusion + Vulnerability Scanning)

Phase 1 introduces a probe framework for local and SSH-based scans.

### SSH Targeting

| Variable | Default | Description |
|----------|---------|-------------|
| `DEMONCLAW_SSH_ALLOWLIST` | - | Comma-separated allowed SSH destinations (exact `user@host` or host-only). If unset, SSH scans are denied unless `DEMONCLAW_SSH_ALLOW_ANY=1`. |
| `DEMONCLAW_SSH_ALLOW_ANY` | `false` | If true, allow SSH scans to any destination (dev only). |

### Commands

Send these via REPL or `POST /ingest` with `{ "content": "..." }`:

- `scan:vuln [--target local|ssh:user@host]`
- `scan:intrusion [--target local|ssh:user@host]`
- `verify [--target local|ssh:user@host]` (safe PoCs, GhostMCP approval required)
- `defend:run [--target local|ssh:user@host] [--apply]` (runs probes + findings + verify (GhostMCP-gated) + remediation plan; with `--apply` it will attempt GhostMCP-gated remediation apply + post-remediation verify)

Remediation (Phase 2 skeleton):

- `remediate:plan [--target local|ssh:user@host]`
- `remediate:apply [--target local|ssh:user@host]` (GhostMCP approval required)

### Remediation toggles

| Variable | Default | Description |
|----------|---------|-------------|
| `DEMONCLAW_REMEDIATE_USE_SUDO` | `true` | If true, remediation actions will run via `sudo -n` (non-interactive). |
| `DEMONCLAW_REMEDIATE_ALLOW_APT_UPGRADE` | `true` | If true, `remediate:apply` may run apt upgrade actions (still requires GhostMCP approval). Set to `false` to disable. |

Notes:
- Remote scans require engagement context when `DEMONCLAW_REQUIRE_ENGAGEMENT=1`.
- `verify` runs read-only checks (for example `sshd -T`) to confirm hardening.
- `scan:*` now also emits findings as evidence (`active_defense.scan.findings`).
- Future phases will add richer findings, policy-driven auto-remediation allowlists, maintenance windows, and post-remediation verification.

## Example .env File

```bash
# Core
DEMONCLAW_HTTP_BIND=0.0.0.0:3000
DATABASE_URL=postgres://user:pass@localhost/demonclaw

# Security
DEMONCLAW_REQUIRE_ENGAGEMENT=1
DEMONCLAW_ENGAGEMENT_ID=engagement-2026-03-31
DEMONCLAW_ALLOW_PRIVATE_ONLY=1
DEMONCLAW_ALLOWED_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
DEMONCLAW_BLOCKED_PORTS=22,2375,2376,3389
DEMONCLAW_MAX_TOOL_LEVEL=intrusive

# SignalGate
SIGNALGATE_BASE_URL=https://api.openai.com/v1
SIGNALGATE_API_KEY=sk-...
SIGNALGATE_MODEL=gpt-4o

# Embeddings (optional)
EMBEDDING_BASE_URL=https://api.openai.com/v1
EMBEDDING_API_KEY=sk-...
EMBEDDING_MODEL=text-embedding-3-small
EMBEDDING_DIMENSION=1536

# Sandbox
DEMONCLAW_SANDBOX_FUEL_LIMIT=10000000
DEMONCLAW_SANDBOX_TIMEOUT_SECS=30

# GhostMCP
GHOSTMCP_AUTO_APPROVE=0
```

## Runtime Behavior

### Evidence Locker
- All envelope events are recorded to `evidence_chain` table
- Each event is hash-linked to the previous (tamper-evident)
- Run `evidence_locker.verify_chain()` to audit integrity

### Memory Optimizer
- Runs hourly in background
- Performs: `ANALYZE`, `VACUUM`, `REINDEX` on `memory_chunks`
- Ensures pgvector indexes stay efficient

### Payload Execution Flow
1. Envelope received → Evidence recorded
2. SignalGate classifies intent
3. SecurityPolicy validates (engagement, CIDR, domains)
4. GhostMCP approves/denies
5. Payload Scanner validates WASM imports
6. Sandbox runs with fuel + timeout limits
7. Result logged to evidence chain
