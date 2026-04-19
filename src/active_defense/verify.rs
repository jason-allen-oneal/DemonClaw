use anyhow::Result;
use serde_json::json;

use super::{
    finders::{detect_intrusion_findings, detect_vuln_findings},
    findings::{Finding, Verification, VerificationResult},
    runner::{CommandRunner, runner_for_target},
    types::Target,
};

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut out = s[..max].to_string();
    out.push_str("\n…(truncated)…\n");
    out
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

fn run_http_get(runner: &dyn CommandRunner, url: &str) -> Result<(String, i32, String, String)> {
    let (code, out, err) = runner.run("curl", &["-sS", "--max-time", "2", url])?;
    if code != -1 {
        return Ok(("curl".to_string(), code, out, err));
    }

    let (code, out, err) = runner.run("wget", &["-qO-", "--timeout=2", url])?;
    Ok(("wget".to_string(), code, out, err))
}

fn run_redis_ping(runner: &dyn CommandRunner) -> Result<(i32, String, String)> {
    runner.run("redis-cli", &["-h", "127.0.0.1", "ping"])
}

fn tcp_connect_loopback(runner: &dyn CommandRunner, port: u16) -> Result<(i32, String, String)> {
    let cmd = format!("</dev/tcp/127.0.0.1/{port}");

    let (code, out, err) = runner.run("timeout", &["2", "bash", "-lc", &cmd])?;
    if code != -1 {
        return Ok((code, out, err));
    }

    runner.run("bash", &["-lc", &cmd])
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
        "redis_exposed" => {
            let (code, stdout, stderr) = run_redis_ping(runner.as_ref())?;
            if code == -1 {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "redis-cli ping (missing)".to_string(),
                    result: VerificationResult::Inconclusive,
                    notes: truncate(&stderr, 2000),
                });
            } else if stdout.trim() == "PONG" {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "redis-cli ping".to_string(),
                    result: VerificationResult::Fail,
                    notes: "redis responded PONG on loopback".to_string(),
                });
            } else {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "redis-cli ping".to_string(),
                    result: VerificationResult::Inconclusive,
                    notes: truncate(&stdout, 2000),
                });
            }
        }
        "elasticsearch_exposed" => {
            let url = "http://127.0.0.1:9200/";
            let (tool, code, stdout, stderr) = run_http_get(runner.as_ref(), url)?;
            if code == -1 {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "http get 127.0.0.1:9200 (missing curl/wget?)".to_string(),
                    result: VerificationResult::Inconclusive,
                    notes: truncate(&stderr, 2000),
                });
            } else if code == 0 {
                let body = stdout.to_ascii_lowercase();
                if body.contains("cluster_name") || body.contains("you know, for search") {
                    out.push(Verification {
                        finding_kind: finding.kind.clone(),
                        target: target.clone(),
                        method: format!("http get 127.0.0.1:9200 via {tool}"),
                        result: VerificationResult::Fail,
                        notes: "elasticsearch-like response on loopback".to_string(),
                    });
                } else {
                    out.push(Verification {
                        finding_kind: finding.kind.clone(),
                        target: target.clone(),
                        method: format!("http get 127.0.0.1:9200 via {tool}"),
                        result: VerificationResult::Inconclusive,
                        notes: truncate(&stdout, 2000),
                    });
                }
            } else {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: format!("http get 127.0.0.1:9200 via {tool}"),
                    result: VerificationResult::Inconclusive,
                    notes: truncate(&format!("exit={code}\n{stderr}"), 4000),
                });
            }
        }
        "mongodb_exposed" => {
            let (code, _out, err) = tcp_connect_loopback(runner.as_ref(), 27017)?;
            if code == 0 {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "tcp connect 127.0.0.1:27017".to_string(),
                    result: VerificationResult::Fail,
                    notes: "TCP connect succeeded on loopback".to_string(),
                });
            } else if code == -1 {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "tcp connect 127.0.0.1:27017 (missing bash/timeout?)".to_string(),
                    result: VerificationResult::Inconclusive,
                    notes: truncate(&err, 2000),
                });
            } else {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "tcp connect 127.0.0.1:27017".to_string(),
                    result: VerificationResult::Inconclusive,
                    notes: format!("connect failed (exit={code})"),
                });
            }
        }
        "memcached_exposed" => {
            let (code, _out, err) = tcp_connect_loopback(runner.as_ref(), 11211)?;
            if code == 0 {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "tcp connect 127.0.0.1:11211".to_string(),
                    result: VerificationResult::Fail,
                    notes: "TCP connect succeeded on loopback".to_string(),
                });
            } else if code == -1 {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "tcp connect 127.0.0.1:11211 (missing bash/timeout?)".to_string(),
                    result: VerificationResult::Inconclusive,
                    notes: truncate(&err, 2000),
                });
            } else {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "tcp connect 127.0.0.1:11211".to_string(),
                    result: VerificationResult::Inconclusive,
                    notes: format!("connect failed (exit={code})"),
                });
            }
        }
        "postgres_exposed" => {
            let (code, _out, err) = tcp_connect_loopback(runner.as_ref(), 5432)?;
            if code == 0 {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "tcp connect 127.0.0.1:5432".to_string(),
                    result: VerificationResult::Fail,
                    notes: "TCP connect succeeded on loopback".to_string(),
                });
            } else if code == -1 {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "tcp connect 127.0.0.1:5432 (missing bash/timeout?)".to_string(),
                    result: VerificationResult::Inconclusive,
                    notes: truncate(&err, 2000),
                });
            } else {
                out.push(Verification {
                    finding_kind: finding.kind.clone(),
                    target: target.clone(),
                    method: "tcp connect 127.0.0.1:5432".to_string(),
                    result: VerificationResult::Inconclusive,
                    notes: format!("connect failed (exit={code})"),
                });
            }
        }
        _ => {}
    }

    Ok(out)
}

pub fn run_verify(target: Target) -> Result<(Vec<Finding>, Vec<Verification>)> {
    let mut findings = detect_vuln_findings(target.clone())?;
    findings.extend(detect_intrusion_findings(target.clone())?);

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
    fn parse_apt_get_upgrade_summary() {
        let s = "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.";
        assert_eq!(parse_apt_get_simulated_upgraded_count(s), Some(0));
        let s2 = "12 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.";
        assert_eq!(parse_apt_get_simulated_upgraded_count(s2), Some(12));
    }
}
