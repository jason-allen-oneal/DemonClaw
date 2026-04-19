use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::{runner::runner_for_target, types::Target};

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

pub fn plan_remediation(target: Target) -> Result<RemediationPlan> {
    let runner = runner_for_target(&target);

    // Phase 2 (skeleton): use `apt-get -s upgrade` to see if upgrades are available.
    let (code, out, err) = runner.run("apt-get", &["-s", "upgrade"])?;

    let use_sudo = std::env::var("DEMONCLAW_REMEDIATE_USE_SUDO")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true);

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

    // Always propose an upgrade action when apt exists.
    // (Future: parse output and only propose if changes exist; add allowlists and security-only mode.)
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
