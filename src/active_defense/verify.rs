use anyhow::Result;
use serde_json::json;

use super::{
    findings::{Finding, Severity, Verification, VerificationResult},
    probes::run_probe,
    runner::{CommandRunner, runner_for_target},
    types::{ProbeKind, Target},
};

fn count_upgradable_packages(stdout: &str) -> usize {
    // `apt list --upgradable` output typically has a header like:
    // "Listing... Done" followed by one package per line.
    stdout
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with("Listing") && !t.starts_with("WARNING")
        })
        .count()
}

fn detect_findings(target: Target) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Surface inventory.
    let ports = run_probe(target.clone(), ProbeKind::ListeningPorts)?;
    if !ports.skipped {
        let s = ports.stdout.to_ascii_lowercase();

        // Very coarse detection based on common `ss`/`netstat` patterns.
        if s.contains(":22") && (s.contains("0.0.0.0:22") || s.contains("[::]:22") || s.contains(":::22")) {
            findings.push(Finding {
                kind: "ssh_exposed".to_string(),
                severity: Severity::Medium,
                title: "SSH appears to be listening on a public-facing bind".to_string(),
                detail: "Detected port 22 listening on a wildcard address. Verify sshd hardening (PermitRootLogin, PasswordAuthentication).".to_string(),
                target: target.clone(),
            });
        }

        if s.contains("0.0.0.0:2375") || s.contains("[::]:2375") || s.contains(":::2375") {
            findings.push(Finding {
                kind: "docker_tcp_2375_exposed".to_string(),
                severity: Severity::Critical,
                title: "Docker TCP 2375 appears exposed".to_string(),
                detail: "Port 2375 is commonly an unauthenticated Docker API. This is frequently a full-host compromise vector.".to_string(),
                target: target.clone(),
            });
        }
    }

    let upg = run_probe(target.clone(), ProbeKind::UpgradablePackages)?;
    if !upg.skipped {
        let n = count_upgradable_packages(&upg.stdout);
        if n > 0 {
            findings.push(Finding {
                kind: "packages_outdated".to_string(),
                severity: if n > 50 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                title: format!("{} packages appear upgradable", n),
                detail: "Pending upgrades often include security fixes. Consider remediation via apt upgrade under change control.".to_string(),
                target: target.clone(),
            });
        }
    }

    // Always record package inventory as evidence, even if it doesn't produce findings yet.
    let _ = run_probe(target.clone(), ProbeKind::PackageInventory)?;

    Ok(findings)
}

fn run_sshd_t(runner: &dyn CommandRunner) -> Result<(i32, String, String)> {
    // `sshd -T` prints effective configuration. Safe read-only.
    Ok(runner.run("sshd", &["-T"])?)
}

fn verify_finding(target: &Target, finding: &Finding) -> Result<Vec<Verification>> {
    let runner = runner_for_target(target);
    let mut out = Vec::new();

    match finding.kind.as_str() {
        "ssh_exposed" => {
            let (code, stdout, stderr) = run_sshd_t(runner.as_ref())?;
            if code == -1 {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "sshd -T (missing)".to_string(),
                    result: VerificationResult::Inconclusive,
                    notes: stderr,
                });
                return Ok(out);
            }

            let cfg = stdout.to_ascii_lowercase();
            let permit_root = cfg.lines().any(|l| l.trim() == "permitrootlogin yes");
            let password_auth = cfg.lines().any(|l| l.trim() == "passwordauthentication yes");

            if permit_root {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "sshd -T: PermitRootLogin".to_string(),
                    result: VerificationResult::Fail,
                    notes: "PermitRootLogin=yes".to_string(),
                });
            } else {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "sshd -T: PermitRootLogin".to_string(),
                    result: VerificationResult::Pass,
                    notes: "PermitRootLogin not 'yes'".to_string(),
                });
            }

            if password_auth {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "sshd -T: PasswordAuthentication".to_string(),
                    result: VerificationResult::Fail,
                    notes: "PasswordAuthentication=yes".to_string(),
                });
            } else {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "sshd -T: PasswordAuthentication".to_string(),
                    result: VerificationResult::Pass,
                    notes: "PasswordAuthentication not 'yes'".to_string(),
                });
            }
        }
        _ => {}
    }

    Ok(out)
}

pub fn run_verify(target: Target) -> Result<(Vec<Finding>, Vec<Verification>)> {
    let findings = detect_findings(target.clone())?;

    let mut verifications = Vec::new();
    for f in &findings {
        let vs = verify_finding(&target, f)?;
        verifications.extend(vs);
    }

    Ok((findings, verifications))
}

pub fn evidence_payload_for_findings(findings: &[Finding]) -> serde_json::Value {
    json!({"findings": findings})
}

pub fn evidence_payload_for_verifications(verifications: &[Verification]) -> serde_json::Value {
    json!({"verifications": verifications})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_upgradable_skips_header() {
        let s = "Listing... Done\n";
        assert_eq!(count_upgradable_packages(s), 0);
        let s2 = "Listing... Done\nfoo/now 1.0 amd64 [upgradable from: 0.9]\n";
        assert_eq!(count_upgradable_packages(s2), 1);
    }
}
