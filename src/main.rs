use anyhow::Result;
use std::sync::Arc;
use tracing::{Level, info, warn};
use tracing_subscriber::FmtSubscriber;

use demonclaw::{
    channels::Channels,
    config::DemonClawConfig,
    darkprompt::DarkPrompt,
    evidence::EvidenceLocker,
    ghostmcp::GhostMcp,
    memory::MemoryManager,
    r#loop::AgentLoop,
    sandbox::{Manifest, Sandbox},
    scanner::Scanner,
    scheduler::Scheduler,
    signalgate::SignalGate,
};

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let cfg = DemonClawConfig::load()?;

    let log_level = match cfg.logging.level.as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    info!("DemonClaw initialized. Core architecture booting...");

    let security_policy = cfg.security_policy();
    let signalgate = SignalGate::new(cfg.signalgate_config())?;
    let sandbox = Sandbox::new()?;
    let ghostmcp = GhostMcp::new();
    let scanner = Scanner::new();
    let darkprompt = DarkPrompt::new();

    let memory_res = MemoryManager::new(&cfg.runtime.database_url).await;

    if let Ok(m) = &memory_res {
        if let Err(e) = m.init_schema().await {
            tracing::warn!("Failed to init schema: {}", e);
        }
    } else {
        tracing::error!("DATABASE NOT REACHABLE. Running core execution test only.");
    }

    if let Ok(memory) = memory_res {
        let evidence_locker = EvidenceLocker::new(memory.pool.clone());
        if let Err(e) = evidence_locker.init_schema().await {
            warn!("Failed to init evidence locker schema: {}", e);
        }

        let memory_optimizer = memory.clone();
        tokio::spawn(async move {
            memory_optimizer.run_optimizer(3600).await;
        });

        let mut agent_loop = AgentLoop::new(
            signalgate,
            memory.clone(),
            sandbox,
            ghostmcp,
            scanner,
            darkprompt,
            security_policy.clone(),
            evidence_locker,
            cfg.runtime.max_concurrent_payloads,
        );

        let (tx, rx) = tokio::sync::mpsc::channel(cfg.runtime.event_buffer);

        let scheduler = Scheduler::new(tx.clone());
        let channels = Arc::new(Channels::new(tx.clone(), cfg.security.clone()));

        let heartbeat_secs = cfg.runtime.scheduler_interval_secs;
        tokio::spawn(async move {
            scheduler.run_heartbeat(heartbeat_secs).await;
        });

        let scheduler_jobs = Scheduler::new(tx.clone());
        scheduler_jobs.spawn_jobs(&cfg.runtime.scheduler_jobs);

        let channels_repl = channels.clone();
        tokio::spawn(async move {
            channels_repl.run_repl().await;
        });

        let channels_http = channels.clone();
        let http_bind = cfg.server.http_bind.clone();
        tokio::spawn(async move {
            channels_http.run_http_server(&http_bind).await;
        });

        agent_loop.run(rx).await?;
    } else {
        warn!("!!! SYSTEM RUNNING WITHOUT PERSISTENT MEMORY !!!");
        info!("Executing Headless Sandbox Test (v2.0 Spec Validation)...");
        let payloads = vec!["test_payload", "network_scanner", "web_enum", "config_auditor"];
        for p in payloads {
            let payload_path = format!(
                "{}/payloads/{}/target/wasm32-wasip1/release/{}.wasm",
                env!("CARGO_MANIFEST_DIR"),
                p,
                p
            );
            if std::path::Path::new(&payload_path).exists() {
                let wasm_bytes = std::fs::read(&payload_path)?;
                info!("Executing {}...", p);

                let manifest = if p == "network_scanner" {
                    Manifest { can_http: vec!["scan.demonclaw.local".to_string()], can_exec: false }
                } else if p == "web_enum" {
                    Manifest { can_http: vec!["target.demonclaw.local".to_string()], can_exec: false }
                } else if p == "config_auditor" {
                    Manifest { can_http: vec!["config.demonclaw.local".to_string()], can_exec: true }
                } else {
                    Manifest { can_http: vec![], can_exec: false }
                };

                sandbox.run_payload(&wasm_bytes, &manifest)?;
            }
        }
    }

    Ok(())
}
