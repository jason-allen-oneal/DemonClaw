use anyhow::Result;

use super::{
    findings::{Finding, Severity},
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

fn tail_auth_log(runner: &dyn CommandRunner) -> Result<(i32, String, String)> {
    // Debian-ish fallback.
    runner.run("tail", &["-n", "500", "/var/log/auth.log"])
}

fn journalctl_ssh(runner: &dyn CommandRunner) -> Result<(i32, String, String)> {
    // Units vary by distro. Try a couple.
    let (code, out, err) = runner.run(
        "journalctl",
        &[
            "-u",
            "ssh",
            "-u",
            "sshd",
            "--since",
            "-24h",
            "--no-pager",
        ],
    )?;
    Ok((code, out, err))
}

fn parse_ssh_auth_summary(text: &str) -> (usize, usize, usize) {
    // (failed, accepted, accepted_root)
    let mut failed = 0;
    let mut accepted = 0;
    let mut accepted_root = 0;

    for line in text.lines() {
        let l = line.to_ascii_lowercase();
        if l.contains("failed password") || l.contains("invalid user") {
            failed += 1;
        }
        if l.contains("accepted password") || l.contains("accepted publickey") {
            accepted += 1;
        }

        if l.contains("accepted password for root") || l.contains("accepted publickey for root") {
            accepted_root += 1;
        }
    }

    (failed, accepted, accepted_root)
}

pub fn detect_vuln_findings(target: Target) -> Result<Vec<Finding>> {
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

        // Other common high-risk services when bound to wildcard addresses.
        // (Heuristic only, based on listening port output.)
        let risky: &[(&str, u16, Severity, &str, &str)] = &[
            (
                "redis_exposed",
                6379,
                Severity::High,
                "Redis appears exposed",
                "Redis is frequently attacked when reachable. Ensure auth, bind, and firewall rules are correct.",
            ),
            (
                "elasticsearch_exposed",
                9200,
                Severity::High,
                "Elasticsearch appears exposed",
                "Elasticsearch can leak data or be abused when reachable without auth.",
            ),
            (
                "mongodb_exposed",
                27017,
                Severity::High,
                "MongoDB appears exposed",
                "MongoDB is frequently attacked when reachable. Ensure auth and firewall rules are correct.",
            ),
            (
                "memcached_exposed",
                11211,
                Severity::High,
                "Memcached appears exposed",
                "Memcached is often abused for data exposure and amplification. Ensure it is not reachable.",
            ),
            (
                "postgres_exposed",
                5432,
                Severity::Medium,
                "PostgreSQL appears exposed",
                "Postgres exposure may be intended, but should be protected by auth and firewall rules.",
            ),
        ];

        for (kind, port, severity, title, detail) in risky.iter() {
            let p = port.to_string();
            let v4 = format!("0.0.0.0:{p}");
            let v6 = format!("[::]:{p}");
            let v6b = format!(":::{p}");
            if s.contains(&v4) || s.contains(&v6) || s.contains(&v6b) {
                findings.push(Finding {
                    kind: (*kind).to_string(),
                    severity: (*severity).clone(),
                    title: (*title).to_string(),
                    detail: (*detail).to_string(),
                    target: target.clone(),
                });
            }
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
                title: format!("{n} packages appear upgradable"),
                detail: "Pending upgrades often include security fixes. Consider remediation via apt upgrade under change control.".to_string(),
                target: target.clone(),
            });
        }
    }

    // Always record package inventory as evidence, even if it doesn't produce findings yet.
    let _ = run_probe(target.clone(), ProbeKind::PackageInventory)?;

    Ok(findings)
}

pub fn detect_intrusion_findings(target: Target) -> Result<Vec<Finding>> {
    let runner = runner_for_target(&target);

    // Prefer journald when available.
    let (code, mut out, _err0) = journalctl_ssh(runner.as_ref())?;
    let mut used = "journalctl";

    if code == -1 || out.trim().is_empty() {
        let (c2, o2, e2) = tail_auth_log(runner.as_ref())?;
        used = "auth.log";
        out = o2;

        if c2 == -1 {
            return Ok(vec![Finding {
                kind: "ssh_auth_log_unavailable".to_string(),
                severity: Severity::Info,
                title: "SSH auth logs unavailable".to_string(),
                detail: format!("Tried journalctl and /var/log/auth.log. stderr: {e2}"),
                target,
            }]);
        }
    }

    let (failed, accepted, accepted_root) = parse_ssh_auth_summary(&out);

    let mut findings = Vec::new();

    if accepted_root > 0 {
        findings.push(Finding {
            kind: "ssh_root_login_accepted_recent".to_string(),
            severity: Severity::High,
            title: "Recent SSH root login accepted".to_string(),
            detail: format!("Detected {accepted_root} root SSH accept events via {used}."),
            target: target.clone(),
        });
    }

    if failed >= 25 {
        findings.push(Finding {
            kind: "ssh_failed_logins_recent".to_string(),
            severity: Severity::Medium,
            title: "High volume of recent SSH auth failures".to_string(),
            detail: format!("Detected {failed} failed SSH auth events via {used}. accepted={accepted}."),
            target: target.clone(),
        });
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_failed_and_accepted() {
        let s = "Failed password for invalid user test from 1.2.3.4\nAccepted publickey for root from 1.2.3.4\n";
        let (failed, accepted, root) = parse_ssh_auth_summary(s);
        assert_eq!(failed, 1);
        assert_eq!(accepted, 1);
        assert_eq!(root, 1);
    }
}
