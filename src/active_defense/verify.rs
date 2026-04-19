use anyhow::Result;
use serde_json::json;

use super::{
    findings::{Finding, Severity, Verification, VerificationResult},
    probes::run_probe,
    runner::{CommandRunner, runner_for_target},
    types::{ProbeKind, Target},
};

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut out = s[..max].to_string();
    out.push_str("\n…(truncated)…\n");
    out
}

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
        if s.contains(":22")
            && (s.contains("0.0.0.0:22") || s.contains("[::]:22") || s.contains(":::22"))
        {
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
    runner.run("sshd", &["-T"])
}

fn run_docker_ping(runner: &dyn CommandRunner) -> Result<(String, i32, String, String)> {
    // Docker Engine unauthenticated ping. Safe read-only.
    let url = "http://127.0.0.1:2375/_ping";

    let (code, out, err) = runner.run("curl", &["-sS", "--max-time", "2", url])?;
    if code != -1 {
        return Ok(("curl".to_string(), code, out, err));
    }

    let (code, out, err) = runner.run("wget", &["-qO-", "--timeout=2", url])?;
    Ok(("wget".to_string(), code, out, err))
}

fn parse_apt_get_simulated_upgraded_count(stdout: &str) -> Option<u32> {
    // Example summary line:
    // "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."
    // We parse the first integer before " upgraded".
    for line in stdout.lines() {
        let t = line.trim();
        if let Some(pos) = t.find(" upgraded") {
            let prefix = &t[..pos];
            if let Some(last_token) = prefix.split_whitespace().next_back()
                && let Ok(n) = last_token.parse::<u32>()
            {
                return Some(n);
            }
        }
    }
    None
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
                    notes: truncate(&stderr, 4000),
                });
                return Ok(out);
            }

            let cfg = stdout.to_ascii_lowercase();
            let permit_root = cfg.lines().any(|l| l.trim() == "permitrootlogin yes");
            let password_auth = cfg
                .lines()
                .any(|l| l.trim() == "passwordauthentication yes");

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
        "docker_tcp_2375_exposed" => {
            let (tool, code, stdout, stderr) = run_docker_ping(runner.as_ref())?;
            if code == -1 {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "docker /_ping (missing curl/wget?)".to_string(),
                    result: VerificationResult::Inconclusive,
                    notes: truncate(&stderr, 2000),
                });
            } else {
                let body = stdout.trim();
                if code == 0 && body == "OK" {
                    out.push(Verification {
                        finding_kind: finding.kind.clone(),
                        target: target.clone(),
                        method: format!("docker /_ping via {tool}"),
                        result: VerificationResult::Fail,
                        notes: "docker API responded OK (unauthenticated)".to_string(),
                    });
                } else if code == 0 {
                    out.push(Verification {
                        finding_kind: finding.kind.clone(),
                        target: target.clone(),
                        method: format!("docker /_ping via {tool}"),
                        result: VerificationResult::Inconclusive,
                        notes: truncate(&format!("unexpected body: {body}"), 2000),
                    });
                } else {
                    out.push(Verification {
                        finding_kind: finding.kind.clone(),
                        target: target.clone(),
                        method: format!("docker /_ping via {tool}"),
                        result: VerificationResult::Inconclusive,
                        notes: truncate(&format!("exit={code}\n{stderr}"), 4000),
                    });
                }
            }
        }
        "packages_outdated" => {
            let (code, stdout, stderr) = runner.run("apt-get", &["-s", "upgrade"])?;
            if code == -1 {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "apt-get -s upgrade (missing)".to_string(),
                    result: VerificationResult::Inconclusive,
                    notes: truncate(&stderr, 2000),
                });
            } else if let Some(n) = parse_apt_get_simulated_upgraded_count(&stdout) {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "apt-get -s upgrade (summary)".to_string(),
                    result: if n == 0 {
                        VerificationResult::Pass
                    } else {
                        VerificationResult::Fail
                    },
                    notes: format!("simulated upgraded count: {n}"),
                });
            } else {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "apt-get -s upgrade (unparsed)".to_string(),
                    result: VerificationResult::Inconclusive,
                    notes: truncate(&stdout, 8000),
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

    #[test]
    fn parse_apt_get_upgrade_summary() {
        let s = "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.";
        assert_eq!(parse_apt_get_simulated_upgraded_count(s), Some(0));
        let s2 = "12 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.";
        assert_eq!(parse_apt_get_simulated_upgraded_count(s2), Some(12));
    }
}
