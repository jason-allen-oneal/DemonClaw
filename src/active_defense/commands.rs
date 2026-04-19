use anyhow::Result;
use serde_json::json;
use tracing::info;

use crate::{
    evidence::EvidenceLocker, ghostmcp::GhostMcp, security::SecurityPolicy, types::Envelope,
};

use super::{
    probes::run_probe,
    types::{ProbeKind, ScanKind, ScanRequest, Target},
};

fn parse_target(tokens: &[&str]) -> Target {
    // Default is local.
    // Accept:
    //   --target local
    //   --target ssh:user@host
    //   --target ssh:host
    for w in tokens.windows(2) {
        if w[0] == "--target" {
            let v = w[1];
            if v == "local" {
                return Target::Local;
            }
            if let Some(rest) = v.strip_prefix("ssh:") {
                return Target::Ssh {
                    destination: rest.to_string(),
                };
            }
        }
    }
    Target::Local
}

fn parse_scan_request(env: &Envelope) -> Option<ScanRequest> {
    let content = env.content.trim();
    let parts: Vec<&str> = content.split_whitespace().collect();
    let head = parts.first().copied().unwrap_or("");

    let target = parse_target(&parts);

    match head {
        "scan:vuln" => Some(ScanRequest {
            kind: ScanKind::Vuln,
            target,
        }),
        "scan:intrusion" => Some(ScanRequest {
            kind: ScanKind::Intrusion,
            target,
        }),
        _ => None,
    }
}

pub async fn handle_active_defense_command(
    env: &Envelope,
    security: &SecurityPolicy,
    ghostmcp: &GhostMcp,
    evidence: &EvidenceLocker,
) -> Result<bool> {
    let Some(req) = parse_scan_request(env) else {
        return Ok(false);
    };

    // Remote operations require explicit engagement context.
    if matches!(req.target, Target::Ssh { .. }) {
        security.check_engagement_context("active_defense_remote_scan")?;
    }

    info!("Active defense scan requested: {:?}", req.kind);
    evidence
        .record(
            "active_defense.scan.started",
            json!({"kind": req.kind, "target": req.target}),
            Some(env.id),
        )
        .await?;

    // Phase 1: just run a couple of probes and record their results.
    let probe_set: &[ProbeKind] = match req.kind {
        ScanKind::Vuln => &[ProbeKind::ListeningPorts, ProbeKind::PackageInventory],
        ScanKind::Intrusion => &[ProbeKind::ListeningPorts],
    };

    for probe in probe_set {
        let probe_target = req.target.clone();
        let res = run_probe(probe_target, probe.clone())?;
        evidence
            .record(
                "active_defense.probe.completed",
                json!({"result": res}),
                Some(env.id),
            )
            .await?;
    }

    // Placeholder: remediation apply is future. Keep GhostMCP wired here.
    // (Prevents dead code / reminds implementers to gate intrusive steps.)
    let _ = ghostmcp;

    evidence
        .record(
            "active_defense.scan.completed",
            json!({"kind": req.kind, "target": req.target}),
            Some(env.id),
        )
        .await?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_defaults_local() {
        let env = Envelope::new("repl", "scan:vuln");
        let req = parse_scan_request(&env).unwrap();
        assert_eq!(req.target, Target::Local);
    }

    #[test]
    fn parse_target_ssh() {
        let env = Envelope::new("repl", "scan:vuln --target ssh:root@10.0.0.5");
        let req = parse_scan_request(&env).unwrap();
        assert_eq!(
            req.target,
            Target::Ssh {
                destination: "root@10.0.0.5".to_string()
            }
        );
    }
}
