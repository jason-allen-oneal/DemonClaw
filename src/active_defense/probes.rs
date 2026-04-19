use anyhow::Result;

use super::{
    runner::{CommandRunner, runner_for_target},
    types::{ProbeKind, ProbeResult, Target},
};

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut out = s[..max].to_string();
    out.push_str("\n…(truncated)…\n");
    out
}

pub fn run_probe(target: Target, probe: ProbeKind) -> Result<ProbeResult> {
    let runner = runner_for_target(&target);

    match probe {
        ProbeKind::ListeningPorts => probe_listening_ports(target, runner.as_ref()),
        ProbeKind::PackageInventory => probe_package_inventory(target, runner.as_ref()),
        ProbeKind::UpgradablePackages => probe_upgradable_packages(target, runner.as_ref()),
        ProbeKind::SshAuthLog => probe_ssh_auth_log(target, runner.as_ref()),
        ProbeKind::Uid0Accounts => probe_uid0_accounts(target, runner.as_ref()),
        ProbeKind::ProcessList => probe_process_list(target, runner.as_ref()),
    }
}

fn probe_listening_ports(target: Target, runner: &dyn CommandRunner) -> Result<ProbeResult> {
    // Prefer `ss` (Kali has it). Fall back to `netstat`.
    let (code, out, err) = runner.run("ss", &["-lntup"])?;
    if code == -1 {
        let (code2, out2, err2) = runner.run("netstat", &["-tulpn"])?;
        let skipped = code2 == -1;
        return Ok(ProbeResult {
            target,
            probe: ProbeKind::ListeningPorts,
            summary: if skipped {
                "skipped (no ss/netstat)".to_string()
            } else {
                "listening ports captured".to_string()
            },
            stdout: truncate(&out2, 32_000),
            stderr: truncate(&err2, 8_000),
            exit_code: code2,
            skipped,
            skip_reason: if skipped {
                Some("missing ss and netstat".to_string())
            } else {
                None
            },
        });
    }

    Ok(ProbeResult {
        target,
        probe: ProbeKind::ListeningPorts,
        summary: "listening ports captured".to_string(),
        stdout: truncate(&out, 32_000),
        stderr: truncate(&err, 8_000),
        exit_code: code,
        skipped: false,
        skip_reason: None,
    })
}

fn probe_package_inventory(target: Target, runner: &dyn CommandRunner) -> Result<ProbeResult> {
    // dpkg-query is the Kali/Debian standard.
    let (code, out, err) = runner.run("dpkg-query", &["-W", "-f=${Package}\t${Version}\n"])?;

    let skipped = code == -1;
    Ok(ProbeResult {
        target,
        probe: ProbeKind::PackageInventory,
        summary: if skipped {
            "skipped (no dpkg-query)".to_string()
        } else {
            "package inventory captured".to_string()
        },
        stdout: truncate(&out, 64_000),
        stderr: truncate(&err, 8_000),
        exit_code: code,
        skipped,
        skip_reason: if skipped {
            Some("missing dpkg-query".to_string())
        } else {
            None
        },
    })
}

fn probe_upgradable_packages(target: Target, runner: &dyn CommandRunner) -> Result<ProbeResult> {
    // `apt list --upgradable` is a safe, read-only way to see pending upgrades.
    let (code, out, err) = runner.run("apt", &["list", "--upgradable"])?;
    let skipped = code == -1;

    Ok(ProbeResult {
        target,
        probe: ProbeKind::UpgradablePackages,
        summary: if skipped {
            "skipped (no apt)".to_string()
        } else {
            "upgradable package list captured".to_string()
        },
        stdout: truncate(&out, 64_000),
        stderr: truncate(&err, 8_000),
        exit_code: code,
        skipped,
        skip_reason: if skipped {
            Some("missing apt".to_string())
        } else {
            None
        },
    })
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

fn probe_ssh_auth_log(target: Target, runner: &dyn CommandRunner) -> Result<ProbeResult> {
    // Best-effort: prefer journald, fall back to /var/log/auth.log.
    let (code, out, err) = runner.run(
        "journalctl",
        &["-u", "ssh", "-u", "sshd", "--since", "-24h", "--no-pager"],
    )?;

    let (code, out, err, used) = if code == -1 || out.trim().is_empty() {
        let (c2, o2, e2) = runner.run("tail", &["-n", "200", "/var/log/auth.log"])?;
        (c2, o2, e2, "auth.log")
    } else {
        (code, out, err, "journalctl")
    };

    let skipped = code == -1;
    let (failed, accepted, accepted_root) = if skipped {
        (0, 0, 0)
    } else {
        parse_ssh_auth_summary(&out)
    };

    Ok(ProbeResult {
        target,
        probe: ProbeKind::SshAuthLog,
        summary: if skipped {
            "skipped (no journalctl/tail)".to_string()
        } else {
            format!(
                "ssh auth log captured via {} (failed={}, accepted={}, accepted_root={})",
                used, failed, accepted, accepted_root
            )
        },
        stdout: truncate(&out, 32_000),
        stderr: truncate(&err, 8_000),
        exit_code: code,
        skipped,
        skip_reason: if skipped {
            Some("missing journalctl/auth.log".to_string())
        } else {
            None
        },
    })
}

fn probe_uid0_accounts(target: Target, runner: &dyn CommandRunner) -> Result<ProbeResult> {
    // Read-only. Extract UID 0 accounts.
    let (code, out, err) = runner.run("awk", &["-F:", "$3==0{print $1}", "/etc/passwd"])?;
    let skipped = code == -1;

    let count = if skipped {
        0
    } else {
        out.lines().filter(|l| !l.trim().is_empty()).count()
    };

    Ok(ProbeResult {
        target,
        probe: ProbeKind::Uid0Accounts,
        summary: if skipped {
            "skipped (no awk)".to_string()
        } else {
            format!("uid0 accounts captured (count={count})")
        },
        stdout: truncate(&out, 8000),
        stderr: truncate(&err, 2000),
        exit_code: code,
        skipped,
        skip_reason: if skipped {
            Some("missing awk".to_string())
        } else {
            None
        },
    })
}

fn probe_process_list(target: Target, runner: &dyn CommandRunner) -> Result<ProbeResult> {
    // Read-only snapshot.
    let (code, out, err) = runner.run(
        "ps",
        &["-eo", "pid,user,comm,args", "--no-headers"],
    )?;
    let skipped = code == -1;
    Ok(ProbeResult {
        target,
        probe: ProbeKind::ProcessList,
        summary: if skipped {
            "skipped (no ps)".to_string()
        } else {
            "process list captured".to_string()
        },
        stdout: truncate(&out, 64_000),
        stderr: truncate(&err, 8_000),
        exit_code: code,
        skipped,
        skip_reason: if skipped {
            Some("missing ps".to_string())
        } else {
            None
        },
    })
}
