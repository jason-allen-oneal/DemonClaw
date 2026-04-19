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
