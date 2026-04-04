# DemonClaw 🦞 [v1.0 Clinical]

**Adversarial AI Orchestration & Purple Team Framework.**

DemonClaw is a specialized, high-security fork of OpenClaw designed for offensive security professionals, red-teamers, and security researchers. It provides a phased, clinical environment for executing exploit chains, monitoring host integrity, and generating tamper-evident evidence.

## 💀 The DemonClaw Advantage

- **Phased Clinical Mandate**: Operations are gated by six clinical phases (RECON_01 through GUARDIAN_06), each with strict Rules of Engagement (ROE).
- **Clinical Intelligence (v1.0)**: Automatic MITRE ATT&CK mapping, OSINT enrichment (GreyNoise/Shodan), and stateful Incident Dossier reconstruction.
- **Evidence Locker**: A cryptographic, tamper-evident ledger that hashes and seals every operational event for post-engagement audit.
- **Panic Protocol**: An instant clinical kill-switch that terminates active agents and sanitizes ephemeral memory.
- **Universal Configuration**: Consolidate your entire engagement (Gateway, ROE, and Intel keys) into a single `demonclaw.universal.json` file.

## 🚀 Quick Start (Clinical Mode)

1. **Provision Your Universal Config**:

   ```bash
   cp schema/universal.schema.json demonclaw.universal.json
   # Edit with your CIDRs, Keys, and ROE Signature
   ```

2. **Engage the Framework**:

   ```bash
   openclaw gateway run --config demonclaw.universal.json
   ```

3. **Audit Your Signal**:
   ```bash
   openclaw security dossier
   ```

## 📖 Documentation

- [Clinical Overview](docs/clinical/overview.md)
- [Intelligence & Mapping](docs/clinical/intel.md)
- [Evidence & Reporting](docs/clinical/evidence-locker.md)
- [Playbooks](docs/clinical/playbooks.md)

---

_Built by BlueDot IT. Systems in Motion._
