use demonclaw::{
    darkprompt::DarkPrompt,
    evidence::EvidenceLocker,
    ghostmcp::GhostMcp,
    r#loop::{AgentLoop, AgentLoopDeps},
    memory::MemoryManager,
    sandbox::Sandbox,
    scanner::Scanner,
    scheduler::Scheduler,
    security::SecurityPolicy,
    signalgate::{SignalGate, SignalGateConfig},
    types::Envelope,
};

fn test_db_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5433/demonclaw".to_string())
}

#[tokio::test]
async fn e2e_payload_to_evidence_flow() -> anyhow::Result<()> {
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

    let scheduler = Scheduler::new(tx.clone());
    let send_handle = tokio::spawn(async move {
        let env = Envelope::new("http", "payload:test_payload");
        tx.send(env).await.expect("failed to send envelope");
        scheduler.run_heartbeat(3600).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    send_handle.abort();
    loop_handle.abort();

    let received = evidence.query_by_kind("job.received", 10).await?;
    let completed = evidence.query_by_kind("job.completed", 10).await?;

    anyhow::ensure!(!received.is_empty(), "expected job.received evidence event");
    anyhow::ensure!(
        !completed.is_empty(),
        "expected job.completed evidence event"
    );

    Ok(())
}
