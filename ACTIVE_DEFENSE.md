# DemonClaw Active Defense (Design, WIP)

DemonClaw’s current core is an orchestrator:

**ingest → classify → policy/approval gate → run (payloads/tools) → evidence**.

This document describes the intended evolution into an **active defense** system that:

- monitors for intrusion indicators (local + remote)
- scans for vulnerabilities (local + remote)
- verifies findings with **safe PoCs** (in-scope, non-destructive)
- remediates/patches automatically under strict guardrails

Kali-first (Debian-family) is the target environment, but probes should degrade gracefully.

## Non-goals

- Autonomous offensive exploitation outside an explicit engagement.
- “Fire and forget” patching without approvals, scope, and auditability.

## Safety model

### Engagement context

For any action that is:
- remote, or
- intrusive, or
- remediation/patching

DemonClaw should require:

- `DEMONCLAW_REQUIRE_ENGAGEMENT=1`
- `DEMONCLAW_ENGAGEMENT_ID=<id>`

### GhostMCP approval

- Scans (read-only) can run without approval.
- **Verification** (safe PoCs) and **remediation** require GhostMCP authorization by default.
- Optional allowlists may be added later for auto-remediation in controlled environments.

### Evidence-first

Everything important becomes evidence:

- probe started/completed + raw outputs (redacted/summarized as needed)
- findings
- verification attempts + results
- remediation plan + applied actions
- post-remediation verification

## Data model (v1)

### Finding

A normalized issue discovered by probes:

- `id`
- `target` (local or ssh host)
- `kind` (string, stable)
- `severity` (info/low/medium/high/critical)
- `title`, `detail`
- `evidence_refs` (event ids)

### Verification

A safe PoC that increases confidence:

- `finding_id`
- `method` (string)
- `result` (pass/fail/inconclusive)
- `notes`

### RemediationPlan

- list of `actions` (each action is explicit and reviewable)
- each action declares whether it is destructive and what it changes

## Execution architecture

### Targets

- **Local**: run host probes on the same machine.
- **Remote (SSH)**: run a constrained set of probe commands over `ssh`.
  - host allowlisting is required by default.

### Probes

A probe is a small unit that can run on a target and produce:

- structured results (JSON)
- optional findings

Examples:
- listening ports inventory (`ss -lntup`)
- package inventory (`dpkg-query -W`)
- auth anomaly summary (`journalctl` / `/var/log/auth.log`)

## Command surface (v1)

Ingest commands as plain text envelopes:

- `scan:vuln [--target local|ssh:user@host]`
- `scan:intrusion [--target ...]`
- `verify [--target ...]` (future)
- `remediate:plan [--target ...]` (future)
- `remediate:apply [--target ...]` (future, GhostMCP-gated)

## Phases

### Phase 1 (this PR series)

- probe framework + target runner (local + ssh)
- minimal probes (ports + packages)
- evidence recording for probe results
- command routing for `scan:*`

### Phase 2

- safe PoC verification runners (read-only checks that increase confidence)
- remediation plan generation (rule-based)
- GhostMCP approval boundary for apply

Status (implemented skeleton):
- `verify --target ...` (GhostMCP-gated) runs safe checks like `sshd -T` to validate hardening.
- `remediate:plan` uses `apt-get -s upgrade` simulation.
- `remediate:apply` runs non-interactive `apt-get -y upgrade` (GhostMCP-gated).

### Phase 3

- continuous intrusion monitoring (polling and/or streaming)
- stateful baselines and drift detection
- auto-remediation allowlists + maintenance windows
