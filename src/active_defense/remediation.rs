use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::{
    finders::detect_vuln_findings,
    runner::runner_for_target,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationAction {
    /// Apply system upgrades using apt-get.
    AptUpgrade {
        /// If true, prefix with `sudo -n`.
        use_sudo: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPlan {
    pub target: Target,
    pub actions: Vec<RemediationAction>,
    /// Evidence-friendly notes (includes simulated output when available).
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyResult {
    pub target: Target,
    pub action: RemediationAction,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

fn bool_from_env(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

pub fn is_action_allowed(action: &RemediationAction) -> bool {
    match action {
        RemediationAction::AptUpgrade { .. } => bool_from_env("DEMONCLAW_REMEDIATE_ALLOW_APT_UPGRADE", false),
    }
}

fn parse_apt_get_simulated_upgraded_count(stdout: &str) -> Option<u32> {
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

pub fn plan_remediation(target: Target) -> Result<RemediationPlan> {
    let runner = runner_for_target(&target);

    let findings = detect_vuln_findings(target.clone())?;
    let wants_apt_upgrade = findings.iter().any(|f| f.kind == "packages_outdated");

    // Use `apt-get -s upgrade` to see if upgrades are available.
    let (code, out, err) = runner.run("apt-get", &["-s", "upgrade"])?;

    let use_sudo = bool_from_env("DEMONCLAW_REMEDIATE_USE_SUDO", true);

    let mut notes = String::new();
    if code == -1 {
        notes.push_str("apt-get not available, skipping remediation planning\n");
        notes.push_str(&format!("stderr: {}\n", truncate(&err, 2000)));
        return Ok(RemediationPlan {
            target,
            actions: vec![],
            notes,
        });
    }

    notes.push_str("apt-get simulation (upgrade)\n\n");
    notes.push_str(&truncate(&out, 32_000));
    if !err.trim().is_empty() {
        notes.push_str("\n\n(stderr)\n");
        notes.push_str(&truncate(&err, 8_000));
    }

    let upgraded = parse_apt_get_simulated_upgraded_count(&out).unwrap_or(0);

    if !wants_apt_upgrade {
        notes.push_str("\n\nNo remediation actions planned: no packages_outdated finding." );
        return Ok(RemediationPlan {
            target,
            actions: vec![],
            notes,
        });
    }

    if upgraded == 0 {
        notes.push_str("\n\nNo remediation actions planned: apt reports 0 upgraded." );
        return Ok(RemediationPlan {
            target,
            actions: vec![],
            notes,
        });
    }

    notes.push_str("\n\nPlanned action: apt upgrade (apply requires DEMONCLAW_REMEDIATE_ALLOW_APT_UPGRADE=1 + GhostMCP approval).\n");

    Ok(RemediationPlan {
        target,
        actions: vec![RemediationAction::AptUpgrade { use_sudo }],
        notes,
    })
}

pub fn apply_action(target: Target, action: RemediationAction) -> Result<ApplyResult> {
    let runner = runner_for_target(&target);

    match action.clone() {
        RemediationAction::AptUpgrade { use_sudo } => {
            // Use env to avoid interactive prompts in unattended runs.
            // Use sudo -n to avoid password prompts.
            let (program, args): (&str, Vec<&str>) = if use_sudo {
                (
                    "sudo",
                    vec![
                        "-n",
                        "env",
                        "DEBIAN_FRONTEND=noninteractive",
                        "apt-get",
                        "-y",
                        "upgrade",
                    ],
                )
            } else {
                (
                    "env",
                    vec!["DEBIAN_FRONTEND=noninteractive", "apt-get", "-y", "upgrade"],
                )
            };

            let (exit_code, stdout, stderr) = runner.run(program, &args)?;
            Ok(ApplyResult {
                target,
                action,
                exit_code,
                stdout: truncate(&stdout, 64_000),
                stderr: truncate(&stderr, 16_000),
            })
        }
    }
}

/// Helper for running a command and capturing output through the target runner.
pub fn run_on_target(
    target: Target,
    program: &str,
    args: &[&str],
) -> Result<(i32, String, String)> {
    let runner = runner_for_target(&target);
    runner.run(program, args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_is_safe_when_apt_missing() {
        // This should never hard-fail even if apt-get is missing in the environment.
        let _ = plan_remediation(Target::Local).unwrap();
    }
}
