use anyhow::Result;
use serde_json::json;
use tokio::sync::{Semaphore, mpsc};
use tracing::{error, info, info_span, warn};

use crate::{
    darkprompt::DarkPrompt,
    evidence::EvidenceLocker,
    ghostmcp::GhostMcp,
    memory::MemoryManager,
    sandbox::{Manifest, Sandbox},
    scanner::Scanner,
    security::SecurityPolicy,
    signalgate::{Intent, SignalGate},
    types::{Envelope, JobState},
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
    payload_slots: Semaphore,
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
        max_concurrent_payloads: usize,
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
            payload_slots: Semaphore::new(max_concurrent_payloads.max(1)),
        }
    }

    pub async fn run(&mut self, mut rx: mpsc::Receiver<Envelope>) -> Result<()> {
        info!("Agent Loop started. Awaiting envelopes...");

        while let Some(env) = rx.recv().await {
            let span = info_span!(
                "agent_loop",
                envelope_id = %env.id,
                source = %env.source,
                received_at = %env.received_at,
            );
            let _entered = span.enter();

            info!("Envelope received: bytes={}", env.content.len());
            self.record_job_state(
                &env,
                JobState::Received,
                json!({"source": env.source, "content": env.content}),
            )
            .await;

            let intent = match self.signalgate.classify_intent(&env.content, None).await {
                Ok(i) => i,
                Err(e) => {
                    warn!("SignalGate classify failed: {}", e);
                    Intent::Unknown
                }
            };

            self.record_job_state(
                &env,
                JobState::Classified,
                json!({"intent": format!("{:?}", intent)}),
            )
            .await;

            match intent {
                Intent::Query => {
                    self.record_job_state(&env, JobState::Running, json!({"pipeline": "query"}))
                        .await;
                    let ctx = self
                        .memory
                        .retrieve_context(&env.content)
                        .await
                        .unwrap_or_default();
                    info!("Query routed. Context chunks: {}", ctx.len());
                    self.record_job_state(
                        &env,
                        JobState::Completed,
                        json!({"pipeline": "query", "context_chunks": ctx.len()}),
                    )
                    .await;
                }
                Intent::Command => {
                    self.record_job_state(&env, JobState::Running, json!({"pipeline": "command"}))
                        .await;
                    if env.content.trim() == "memory:compact" {
                        if let Err(e) = self.memory.compact_memory().await {
                            self.record_job_state(
                                &env,
                                JobState::Failed,
                                json!({"pipeline": "command", "error": e.to_string()}),
                            )
                            .await;
                            continue;
                        }
                    }
                    info!("Command routed.");
                    self.record_job_state(
                        &env,
                        JobState::Completed,
                        json!({"pipeline": "command"}),
                    )
                    .await;
                }
                Intent::AttackPayload => {
                    self.record_job_state(&env, JobState::Running, json!({"pipeline": "payload"}))
                        .await;
                    if let Some(name) = env.content.trim().strip_prefix("payload:") {
                        let name = name.trim();
                        info!("Payload request: {}", name);

                        if let Err(e) = self
                            .security_policy
                            .check_engagement_context("payload_execution")
                        {
                            error!("Security policy blocked payload {}: {}", name, e);
                            self.record_job_state(
                                &env,
                                JobState::Denied,
                                json!({"payload": name, "error": e.to_string()}),
                            )
                            .await;
                            continue;
                        }

                        let approved = self.ghostmcp.approve_payload(name).await.unwrap_or(false);
                        if !approved {
                            warn!("GhostMCP denied payload execution: {}", name);
                            self.record_job_state(
                                &env,
                                JobState::Denied,
                                json!({"payload": name, "error": "ghostmcp denied"}),
                            )
                            .await;
                            continue;
                        }

                        let _permit = match self.payload_slots.acquire().await {
                            Ok(p) => p,
                            Err(e) => {
                                self.record_job_state(
                                    &env,
                                    JobState::Failed,
                                    json!({"payload": name, "error": e.to_string()}),
                                )
                                .await;
                                continue;
                            }
                        };

                        let wasm_bytes = match self.darkprompt.prepare_payload(name) {
                            Ok(b) => b,
                            Err(e) => {
                                error!("Failed to load payload {}: {}", name, e);
                                self.record_job_state(
                                    &env,
                                    JobState::Failed,
                                    json!({"payload": name, "error": e.to_string()}),
                                )
                                .await;
                                continue;
                            }
                        };

                        if let Err(e) = self.scanner.scan(&wasm_bytes) {
                            error!("Payload Scanner blocked {}: {}", name, e);
                            self.record_job_state(
                                &env,
                                JobState::Denied,
                                json!({"payload": name, "error": e.to_string()}),
                            )
                            .await;
                            continue;
                        }

                        let manifest = Manifest {
                            can_http: vec![],
                            can_exec: false,
                        };
                        if let Err(e) = self.sandbox.run_payload(&wasm_bytes, &manifest) {
                            error!("Payload {} execution failed: {}", name, e);
                            self.record_job_state(
                                &env,
                                JobState::Failed,
                                json!({"payload": name, "error": e.to_string()}),
                            )
                            .await;
                            continue;
                        }

                        self.record_job_state(&env, JobState::Completed, json!({"payload": name}))
                            .await;
                    } else {
                        info!("AttackPayload intent but no payload directive. Ignored.");
                        self.record_job_state(
                            &env,
                            JobState::Ignored,
                            json!({"reason": "missing payload directive"}),
                        )
                        .await;
                    }
                }
                Intent::Unknown => {
                    info!("Unknown intent. No action.");
                    self.record_job_state(
                        &env,
                        JobState::Ignored,
                        json!({"reason": "unknown intent"}),
                    )
                    .await;
                }
            }
        }

        Ok(())
    }

    async fn record_job_state(&self, env: &Envelope, state: JobState, detail: serde_json::Value) {
        if let Err(e) = self
            .evidence_locker
            .record(
                format!("job.{}", format!("{:?}", state).to_ascii_lowercase()),
                json!({
                    "envelope_id": env.id,
                    "state": state,
                    "detail": detail,
                }),
                Some(env.id),
            )
            .await
        {
            warn!("Failed to record job state: {}", e);
        }
    }
}
