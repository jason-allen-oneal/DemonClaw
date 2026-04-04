use anyhow::Result;
use serde_json::json;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::{
    darkprompt::DarkPrompt,
    evidence::EvidenceLocker,
    ghostmcp::GhostMcp,
    memory::MemoryManager,
    sandbox::{Manifest, Sandbox},
    scanner::Scanner,
    security::SecurityPolicy,
    signalgate::{Intent, SignalGate},
    types::Envelope,
};

/// The core asynchronous agent loop.
pub struct AgentLoop {
    signalgate: SignalGate,
    memory: MemoryManager,
    sandbox: Sandbox,
    ghostmcp: GhostMcp,
    scanner: Scanner,
    darkprompt: DarkPrompt,
    security_policy: SecurityPolicy,
    evidence_locker: EvidenceLocker,
}

impl AgentLoop {
    pub fn new(
        signalgate: SignalGate,
        memory: MemoryManager,
        sandbox: Sandbox,
        ghostmcp: GhostMcp,
        scanner: Scanner,
        darkprompt: DarkPrompt,
        security_policy: SecurityPolicy,
        evidence_locker: EvidenceLocker,
    ) -> Self {
        info!("Core Agent Loop constructed with SecurityPolicy + EvidenceLocker.");
        Self {
            signalgate,
            memory,
            sandbox,
            ghostmcp,
            scanner,
            darkprompt,
            security_policy,
            evidence_locker,
        }
    }

    pub async fn run(&mut self, mut rx: mpsc::Receiver<Envelope>) -> Result<()> {
        info!("Agent Loop started. Awaiting envelopes...");

        while let Some(env) = rx.recv().await {
            info!("Envelope received: id={} bytes={}", env.id, env.content.len());

            // Record evidence event
            if let Err(e) = self.evidence_locker.record(
                "envelope.received",
                json!({"content": env.content, "source": env.source}),
                Some(env.id),
            ).await {
                warn!("Failed to record evidence: {}", e);
            }

            // Route
            let intent = match self.signalgate.classify_intent(&env.content, None).await {
                Ok(i) => i,
                Err(e) => {
                    warn!("SignalGate classify failed: {}", e);
                    Intent::Unknown
                }
            };

            match intent {
                Intent::Query => {
                    let _ctx = self.memory.retrieve_context(&env.content).await.unwrap_or_default();
                    info!("Query routed. Context chunks: {}", _ctx.len());
                }
                Intent::Command => {
                    // Minimal command surface
                    if env.content.trim() == "memory:compact" {
                        let _ = self.memory.compact_memory().await;
                    }
                    info!("Command routed.");
                }
                Intent::AttackPayload => {
                    // Minimal: allow explicit payload run via "payload:<name>"
                    if let Some(name) = env.content.trim().strip_prefix("payload:") {
                        let name = name.trim();
                        info!("Payload request: {}", name);

                        // Check engagement context if required
                        if let Err(e) = self.security_policy.check_engagement_context("payload_execution") {
                            tracing::error!("Security policy blocked payload {}: {}", name, e);
                            continue;
                        }

                        // GhostMCP boundary
                        let approved = self.ghostmcp.approve_payload(name).await.unwrap_or(false);
                        if !approved {
                            tracing::warn!("GhostMCP denied payload execution: {}", name);
                            continue;
                        }

                        let wasm_bytes = match self.darkprompt.prepare_payload(name) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::error!("Failed to load payload {}: {}", name, e);
                                continue;
                            }
                        };

                        // Scanner gate
                        if let Err(e) = self.scanner.scan(&wasm_bytes) {
                            tracing::error!("Payload Scanner blocked {}: {}", name, e);
                            continue;
                        }

                        let manifest = Manifest { can_http: vec![], can_exec: false };
                        if let Err(e) = self.sandbox.run_payload(&wasm_bytes, &manifest) {
                            tracing::error!("Payload {} execution failed: {}", name, e);
                        }
                    } else {
                        info!("AttackPayload intent but no payload directive. Ignored.");
                    }
                }
                Intent::Unknown => {
                    info!("Unknown intent. No action.");
                }
            }
        }

        Ok(())
    }
}
