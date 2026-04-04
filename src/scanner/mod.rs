use anyhow::{Result, anyhow, bail};
use tracing::{info, warn};
use wasmparser::{Operator, Parser, Payload};

/// Payload Scanner.
/// Statically analyzes WASM payloads before they load into wasmtime.
pub struct Scanner;

impl Scanner {
    pub fn new() -> Self {
        info!("Payload Scanner (Pre-Execution Gate) initialized.");
        Self
    }

    /// Analyzes the WASM binary for requested capabilities, hidden imports, and malicious instruction patterns.
    pub fn scan(&self, wasm_bytes: &[u8]) -> Result<bool> {
        info!("Scanning payload for malicious patterns and evaluating capability requests...");

        if wasm_bytes.is_empty() {
            bail!("WASM payload is empty");
        }

        let mut suspicious_imports = Vec::new();
        let mut capability_requests = Vec::new();
        let mut suspicious_instructions = Vec::new();

        for payload in Parser::new(0).parse_all(wasm_bytes) {
            match payload? {
                Payload::ImportSection(section) => {
                    for import in section {
                        let import = import?;
                        let module = import.module;
                        let field = import.name;
                        let import_path = format!("{module}::{field}");

                        if !is_allowlisted_import(module, field) {
                            suspicious_imports.push(import_path.clone());
                        }

                        if let Some(request) = capability_request(module, field) {
                            capability_requests.push(request.to_string());
                        }
                    }
                }
                Payload::CodeSectionEntry(body) => {
                    let mut reader = body.get_operators_reader()?;
                    while !reader.eof() {
                        let op = reader.read()?;
                        if let Some(pattern) = suspicious_operator(&op) {
                            suspicious_instructions.push(pattern.to_string());
                        }
                    }
                }
                _ => {}
            }
        }

        if !capability_requests.is_empty() {
            warn!(
                "Scanner detected requested capabilities: {}",
                capability_requests.join(", ")
            );
        }

        if !suspicious_imports.is_empty() {
            return Err(anyhow!(
                "Scanner blocked payload due to non-allowlisted imports: {}",
                suspicious_imports.join(", ")
            ));
        }

        if !suspicious_instructions.is_empty() {
            return Err(anyhow!(
                "Scanner blocked payload due to suspicious instruction patterns: {}",
                suspicious_instructions.join(", ")
            ));
        }

        Ok(true)
    }
}

fn is_allowlisted_import(module: &str, field: &str) -> bool {
    match module {
        "wasi_snapshot_preview1" => true,
        "env" => matches!(field, "log" | "http_request" | "exec_command"),
        _ => false,
    }
}

fn capability_request(module: &str, field: &str) -> Option<&'static str> {
    match (module, field) {
        ("env", "http_request") => Some("can_http"),
        ("env", "exec_command") => Some("can_exec"),
        (_, name) if contains_network_pattern(name) => Some("can_http"),
        (_, name) if contains_exec_pattern(name) => Some("can_exec"),
        _ => None,
    }
}

fn contains_network_pattern(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    ["http", "https", "socket", "dns", "tcp", "udp"]
        .iter()
        .any(|needle| value.contains(needle))
}

fn contains_exec_pattern(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    ["exec", "spawn", "system", "process", "fork"]
        .iter()
        .any(|needle| value.contains(needle))
}

fn suspicious_operator(op: &Operator<'_>) -> Option<&'static str> {
    match op {
        Operator::CallIndirect { .. } => Some("call_indirect"),
        Operator::ReturnCallIndirect { .. } => Some("return_call_indirect"),
        Operator::RefFunc { .. } => Some("ref_func"),
        _ => None,
    }
}
