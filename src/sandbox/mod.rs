use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use tracing::info;
use wasmparser::{Parser, Payload};
use wasmtime::*;
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::p1::{WasiP1Ctx, add_to_linker_sync};

pub struct Sandbox {
    engine: Engine,
    /// Default fuel limit per payload (instructions)
    default_fuel: u64,
    /// Default timeout per payload
    default_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct Manifest {
    pub can_http: Vec<String>,
    pub can_exec: bool,
}

struct SandboxState {
    wasi: WasiP1Ctx,
    manifest: Manifest,
}

impl Sandbox {
    pub fn new() -> Result<Self> {
        info!("Initializing WebAssembly Sandbox (wasmtime) with fuel + timeout limits...");
        
        let mut config = Config::new();
        // Enable fuel for instruction counting
        config.consume_fuel(true);
        // Enable epoch interruption for timeouts
        config.epoch_interruption(true);
        
        let engine = Engine::new(&config)?;
        
        // Default limits (can be overridden via env vars)
        let default_fuel = std::env::var("DEMONCLAW_SANDBOX_FUEL_LIMIT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10_000_000); // 10M instructions default
        
        let default_timeout_secs = std::env::var("DEMONCLAW_SANDBOX_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30); // 30 seconds default
        
        Ok(Self {
            engine,
            default_fuel,
            default_timeout: Duration::from_secs(default_timeout_secs),
        })
    }

    /// Run a module, subjected to the scanner and capabilities
    pub fn run_payload(&self, wasm_bytes: &[u8], manifest: &Manifest) -> Result<()> {
        validate_manifest_requests(wasm_bytes, manifest)?;

        info!("Compiling WASM payload...");
        let module = Module::new(&self.engine, wasm_bytes)?;

        let wasi = WasiCtxBuilder::new().inherit_stdio().build_p1();
        let mut store = Store::new(
            &self.engine,
            SandboxState {
                wasi,
                manifest: manifest.clone(),
            },
        );

        // Apply fuel limit (instruction budget)
        store.set_fuel(self.default_fuel)?;
        info!("Fuel limit set: {} instructions", self.default_fuel);

        // Apply timeout via epoch interruption
        store.set_epoch_deadline(self.default_timeout.as_secs());
        info!("Timeout set: {} seconds", self.default_timeout.as_secs());

        let mut linker = Linker::new(&self.engine);
        add_to_linker_sync(&mut linker, |state: &mut SandboxState| &mut state.wasi)?;

        linker.func_wrap(
            "env",
            "log",
            |mut caller: Caller<'_, SandboxState>, ptr: i32, len: i32| {
                match read_guest_string(&mut caller, ptr, len) {
                    Ok(msg) => info!("Payload Log: {}", msg),
                    Err(err) => info!("Payload Log decode error: {}", err),
                }
            },
        )?;

        linker.func_wrap(
            "env",
            "http_request",
            |mut caller: Caller<'_, SandboxState>, ptr: i32, len: i32| -> i32 {
                let request_target = match read_guest_string(&mut caller, ptr, len) {
                    Ok(target) => target,
                    Err(err) => {
                        info!("Payload HTTP request parse failure: {}", err);
                        return -1;
                    }
                };

                match enforce_http_permission(&caller.data().manifest, &request_target) {
                    Ok(()) => {
                        info!("Payload HTTP request approved for target: {}", request_target);
                        0
                    }
                    Err(err) => {
                        info!("Payload HTTP request denied: {}", err);
                        -1
                    }
                }
            },
        )?;

        linker.func_wrap(
            "env",
            "exec_command",
            |mut caller: Caller<'_, SandboxState>, ptr: i32, len: i32| -> i32 {
                let command = match read_guest_string(&mut caller, ptr, len) {
                    Ok(cmd) => cmd,
                    Err(err) => {
                        info!("Payload exec command parse failure: {}", err);
                        return -1;
                    }
                };

                if let Err(err) = enforce_exec_permission(&caller.data().manifest, &command) {
                    info!("Payload exec command denied: {}", err);
                    return -1;
                }

                let mut parts = command.split_whitespace();
                let Some(program) = parts.next() else {
                    info!("Payload exec command denied: empty command");
                    return -1;
                };
                let args: Vec<&str> = parts.collect();

                match Command::new(program).args(args).status() {
                    Ok(status) => status.code().unwrap_or(-1),
                    Err(err) => {
                        info!("Payload exec bridge failed: {}", err);
                        -1
                    }
                }
            },
        )?;

        info!("Instantiating WASM module...");
        let instance = linker.instantiate(&mut store, &module)?;

        info!("Executing payload entrypoint...");
        if let Some(func) = instance.get_typed_func::<(), ()>(&mut store, "run").ok() {
            func.call(&mut store, ())?;
        } else if let Some(func) = instance.get_typed_func::<(), ()>(&mut store, "_start").ok() {
            func.call(&mut store, ())?;
        } else {
            info!("No _start or run function found in payload.");
        }

        Ok(())
    }
}

fn read_guest_string(caller: &mut Caller<'_, SandboxState>, ptr: i32, len: i32) -> Result<String> {
    if ptr < 0 || len < 0 {
        bail!("Guest provided negative pointer or length");
    }

    let memory = caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
        .ok_or_else(|| anyhow!("WASM module does not export linear memory"))?;

    let mut buf = vec![0; len as usize];
    memory.read(caller, ptr as usize, &mut buf)?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn validate_manifest_requests(wasm_bytes: &[u8], manifest: &Manifest) -> Result<()> {
    for payload in Parser::new(0).parse_all(wasm_bytes) {
        if let Payload::ImportSection(imports) = payload? {
            for import in imports {
                let import = import?;
                match (import.module, import.name) {
                    ("env", "http_request") if manifest.can_http.is_empty() => {
                        bail!("Payload requests http capability, but manifest can_http is empty");
                    }
                    ("env", "exec_command") if !manifest.can_exec => {
                        bail!("Payload requests exec capability, but manifest can_exec is false");
                    }
                    ("env", "log" | "http_request" | "exec_command")
                    | ("wasi_snapshot_preview1", _) => {}
                    _ => {
                        bail!(
                            "Payload imports non-allowlisted host function '{}::{}'",
                            import.module,
                            import.name
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

fn enforce_http_permission(manifest: &Manifest, request_target: &str) -> Result<()> {
    if manifest.can_http.is_empty() {
        bail!("HTTP blocked: manifest has no can_http allowlist entries");
    }

    let host = extract_host(request_target)?;
    let allowed = manifest
        .can_http
        .iter()
        .any(|rule| host_matches_rule(&host, rule));

    if !allowed {
        bail!("HTTP blocked: target '{}' is not in manifest allowlist", host);
    }

    Ok(())
}

fn enforce_exec_permission(manifest: &Manifest, command: &str) -> Result<()> {
    if !manifest.can_exec {
        bail!("Process execution blocked: manifest can_exec is false");
    }

    if command.trim().is_empty() {
        bail!("Process execution blocked: empty command");
    }

    let forbidden = ['|', '&', ';', '>', '<', '`', '$'];
    if command.chars().any(|c| forbidden.contains(&c)) {
        bail!("Process execution blocked: command contains forbidden shell meta characters");
    }

    Ok(())
}

fn extract_host(request_target: &str) -> Result<String> {
    if request_target.contains("://") {
        let parsed = reqwest::Url::parse(request_target)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("Request URL has no host"))?;
        return Ok(host.to_string());
    }

    if let Some(host) = request_target.split('/').next() {
        if !host.trim().is_empty() {
            return Ok(host.to_string());
        }
    }

    bail!("Unable to parse request target host from '{}'", request_target)
}

fn host_matches_rule(host: &str, rule: &str) -> bool {
    if rule.eq_ignore_ascii_case(host) {
        return true;
    }

    if let (Ok(host_ip), Some((network_ip, prefix))) = (Ipv4Addr::from_str(host), parse_cidr(rule)) {
        return ipv4_in_cidr(host_ip, network_ip, prefix);
    }

    false
}

fn parse_cidr(value: &str) -> Option<(Ipv4Addr, u32)> {
    let (network, prefix) = value.split_once('/')?;
    let network_ip = Ipv4Addr::from_str(network).ok()?;
    let prefix = prefix.parse::<u32>().ok()?;
    if prefix <= 32 {
        Some((network_ip, prefix))
    } else {
        None
    }
}

fn ipv4_in_cidr(ip: Ipv4Addr, network: Ipv4Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };

    (u32::from(ip) & mask) == (u32::from(network) & mask)
}
