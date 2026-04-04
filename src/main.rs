use anyhow::Result;
use tracing::{info, Level, warn};
use tracing_subscriber::FmtSubscriber;
use std::env;
use std::sync::Arc;

use demonclaw::{
    config::DemonClawConfig,
    security::SecurityPolicy,
    r#loop::AgentLoop,
    signalgate::{SignalGate, SignalGateConfig},
    memory::MemoryManager,
    sandbox::{Sandbox, Manifest},
    ghostmcp::GhostMcp,
    scanner::Scanner,
    darkprompt::DarkPrompt,
    scheduler::Scheduler,
    channels::Channels,
    evidence::EvidenceLocker,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize environment variables from .env
    dotenvy::dotenv().ok();

    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    info!("DemonClaw initialized. Core architecture booting...");

    let cfg = DemonClawConfig::load_from_env();
    let security_policy = SecurityPolicy::load_from_env();

    let db_url = env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://localhost/demonclaw".to_string());
    let signalgate_config = SignalGateConfig::load_from_env();
    let signalgate = SignalGate::new(signalgate_config)?;
    let sandbox = Sandbox::new()?;
    let ghostmcp = GhostMcp::new();
    let scanner = Scanner::new();
    let darkprompt = DarkPrompt::new();

    let memory_res = MemoryManager::new(&db_url).await;
    
    if let Ok(m) = &memory_res {
        if let Err(e) = m.init_schema().await {
            tracing::warn!("Failed to init schema: {}", e);
        }
    } else {
        tracing::error!("DATABASE NOT REACHABLE. Running core execution test only.");
    }

    if let Ok(memory) = memory_res {
        // Initialize Evidence Locker
        let evidence_locker = EvidenceLocker::new(memory.pool.clone());
        if let Err(e) = evidence_locker.init_schema().await {
            warn!("Failed to init evidence locker schema: {}", e);
        }

        // Start Memory Optimizer background task
        let memory_optimizer = memory.clone();
        tokio::spawn(async move {
            memory_optimizer.run_optimizer(3600).await; // hourly
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
        );

        // Shared envelope bus
        let (tx, rx) = tokio::sync::mpsc::channel(256);

        let scheduler = Scheduler::new(tx.clone());
        let channels = Arc::new(Channels::new(tx.clone(), cfg.security.clone()));

        // Start Scheduler
        tokio::spawn(async move {
            scheduler.run_heartbeat(60).await;
        });

        // Start REPL
        let channels_repl = channels.clone();
        tokio::spawn(async move {
            channels_repl.run_repl().await;
        });

        // Start HTTP Ingest
        let channels_http = channels.clone();
        let http_bind = cfg.server.http_bind.clone();
        tokio::spawn(async move {
            channels_http.run_http_server(&http_bind).await;
        });

        // Run loop
        agent_loop.run(rx).await?;
    } else {
        warn!("!!! SYSTEM RUNNING WITHOUT PERSISTENT MEMORY !!!");
        info!("Executing Headless Sandbox Test (v2.0 Spec Validation)...");
        let payloads = vec!["test_payload", "network_scanner", "web_enum", "config_auditor"];
        for p in payloads {
            let payload_path = format!("/home/rev/projects/demonclaw/DemonClaw/payloads/{}/target/wasm32-wasip1/release/{}.wasm", p, p);
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
