use anyhow::{Result, bail};
use std::process::Command;

use super::types::Target;

#[derive(Debug, Clone, Default)]
pub struct SshPolicy {
    /// Comma-separated allowlist entries (hostnames or exact destinations).
    /// If empty, SSH is denied unless `allow_any` is true.
    pub allowlist: Vec<String>,
    pub allow_any: bool,
}

impl SshPolicy {
    pub fn from_env() -> Self {
        let allow_any = std::env::var("DEMONCLAW_SSH_ALLOW_ANY")
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);

        let allowlist = std::env::var("DEMONCLAW_SSH_ALLOWLIST")
            .ok()
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Self {
            allowlist,
            allow_any,
        }
    }

    pub fn check_destination(&self, destination: &str) -> Result<()> {
        if self.allow_any {
            return Ok(());
        }
        if self.allowlist.is_empty() {
            bail!(
                "SSH destination '{}' denied (no allowlist configured). Set DEMONCLAW_SSH_ALLOWLIST or DEMONCLAW_SSH_ALLOW_ANY=1",
                destination
            );
        }

        let dest = destination.trim();
        if self.allowlist.iter().any(|a| a == dest) {
            return Ok(());
        }

        // Also allowlist by host (strip user@ if present).
        let host = dest.split('@').next_back().unwrap_or(dest);
        if self.allowlist.iter().any(|a| a == host) {
            return Ok(());
        }

        bail!("SSH destination '{}' not allowlisted", destination);
    }
}

pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<(i32, String, String)>;
}

#[derive(Debug, Clone)]
pub struct LocalRunner;

impl CommandRunner for LocalRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<(i32, String, String)> {
        let out = Command::new(program).args(args).output();
        match out {
            Ok(o) => Ok((
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stdout).to_string(),
                String::from_utf8_lossy(&o.stderr).to_string(),
            )),
            Err(e) => Ok((-1, String::new(), e.to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SshRunner {
    pub destination: String,
    pub policy: SshPolicy,
}

fn shell_escape(s: &str) -> String {
    // Single-quote shell escaping.
    // abc -> 'abc'
    // a'b -> 'a'"'"'b'
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\"'\"'");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

impl CommandRunner for SshRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<(i32, String, String)> {
        self.policy.check_destination(&self.destination)?;

        // Encode as a single remote command string, with shell-escaped argv to avoid
        // injection and preserve spaces/special characters.
        let mut remote = shell_escape(program);
        for a in args {
            remote.push(' ');
            remote.push_str(&shell_escape(a));
        }

        let out = Command::new("ssh")
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=accept-new",
                &self.destination,
                &remote,
            ])
            .output();

        match out {
            Ok(o) => Ok((
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stdout).to_string(),
                String::from_utf8_lossy(&o.stderr).to_string(),
            )),
            Err(e) => Ok((-1, String::new(), e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_escape_wraps_and_escapes_single_quotes() {
        assert_eq!(shell_escape("abc"), "'abc'");
        assert_eq!(shell_escape("a'b"), "'a'\"'\"'b'");
        assert_eq!(shell_escape(""), "''");
    }
}

pub fn runner_for_target(target: &Target) -> Box<dyn CommandRunner + Send + Sync> {
    match target {
        Target::Local => Box::new(LocalRunner),
        Target::Ssh { destination } => Box::new(SshRunner {
            destination: destination.clone(),
            policy: SshPolicy::from_env(),
        }),
    }
}
