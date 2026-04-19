use demonclaw::{
    darkprompt::DarkPrompt,
    evidence::EvidenceLocker,
    ghostmcp::GhostMcp,
    r#loop::{AgentLoop, AgentLoopDeps},
    memory::MemoryManager,
    sandbox::Sandbox,
    scanner::Scanner,
    security::SecurityPolicy,
    signalgate::{SignalGate, SignalGateConfig},
    types::Envelope,
};

fn test_payload_wasm_path() -> String {
    format!(
        "{}/payloads/test_payload/target/wasm32-wasip1/release/test_payload.wasm",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn test_db_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5433/demonclaw".to_string())
}

#[tokio::test]
async fn e2e_payload_to_evidence_flow() -> anyhow::Result<()> {
    let wasm_path = test_payload_wasm_path();
    if !std::path::Path::new(&wasm_path).exists() {
        println!(
            "Skipping e2e_payload_to_evidence_flow, payload wasm not built: {}",
            wasm_path
        );
        return Ok(());
    }

    let memory = match MemoryManager::new(&test_db_url()).await {
        Ok(mm) => mm,
        Err(e) => {
            println!(
                "Skipping e2e_payload_to_evidence_flow, database unavailable: {}",
                e
            );
            return Ok(());
        }
    };

    memory.init_schema().await?;
    let evidence = EvidenceLocker::new(memory.pool.clone());
    evidence.init_schema().await?;

    let signalgate = SignalGate::new(SignalGateConfig::default())?;
    let sandbox = Sandbox::new()?;
    let ghostmcp = GhostMcp::new();
    let scanner = Scanner::new();
    let darkprompt = DarkPrompt::new();
    let security = SecurityPolicy::default();

    let mut agent_loop = AgentLoop::new(AgentLoopDeps {
        signalgate,
        memory,
        sandbox,
        ghostmcp,
        scanner,
        darkprompt,
        security_policy: security,
        evidence_locker: evidence.clone(),
        max_concurrent_payloads: 1,
    });

    unsafe {
        std::env::set_var("GHOSTMCP_AUTO_APPROVE", "1");
    }

    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let loop_handle = tokio::spawn(async move { agent_loop.run(rx).await });

    let env = Envelope::new("http", "payload:test_payload");
    tx.send(env).await.expect("failed to send envelope");
    drop(tx);

    // Wait for the loop to drain the channel and exit.
    tokio::time::timeout(std::time::Duration::from_secs(5), loop_handle).await???;

    let received = evidence.query_by_kind("job.received", 10).await?;
    let completed = evidence.query_by_kind("job.completed", 10).await?;

    anyhow::ensure!(!received.is_empty(), "expected job.received evidence event");
    anyhow::ensure!(
        !completed.is_empty(),
        "expected job.completed evidence event"
    );

    Ok(())
}
