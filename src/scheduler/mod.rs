use crate::{config::ScheduledJobConfig, types::Envelope};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{info, warn};

pub struct Scheduler {
    tx: mpsc::Sender<Envelope>,
}

impl Scheduler {
    pub fn new(tx: mpsc::Sender<Envelope>) -> Self {
        Self { tx }
    }

    pub async fn run_heartbeat(&self, interval_secs: u64) {
        let mut ticker = interval(Duration::from_secs(interval_secs));
        info!("Heartbeat scheduler started ({}s)", interval_secs);

        loop {
            ticker.tick().await;
            let env = Envelope::new("scheduler", "HEARTBEAT");
            if let Err(e) = self.tx.send(env).await {
                tracing::error!("Scheduler failed to enqueue heartbeat: {}", e);
                break;
            }
        }
    }

    pub fn spawn_jobs(&self, jobs: &[ScheduledJobConfig]) {
        for job in jobs.iter().cloned() {
            let tx = self.tx.clone();
            tokio::spawn(async move {
                if let Some(interval_secs) = job.interval_secs {
                    let mut ticker = interval(Duration::from_secs(interval_secs.max(1)));
                    info!("Scheduled job started: {} every {}s", job.name, interval_secs);
                    loop {
                        ticker.tick().await;
                        let mut env = Envelope::new(
                            if job.source.is_empty() { "scheduler" } else { &job.source },
                            &job.content,
                        );
                        env.metadata = serde_json::json!({
                            "job_name": job.name,
                            "schedule_kind": "interval",
                            "interval_secs": interval_secs,
                        });
                        if let Err(err) = tx.send(env).await {
                            warn!("Scheduled job enqueue failed: {}", err);
                            break;
                        }
                    }
                } else if job.cron.is_some() {
                    warn!("Cron expression support is declared but not implemented for job {}", job.name);
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_scheduler_heartbeat() {
        let (tx, mut rx) = mpsc::channel(1);
        let scheduler = Scheduler::new(tx);

        let handle = tokio::spawn(async move {
            scheduler.run_heartbeat(1).await;
        });

        let env = rx.recv().await.expect("Should receive heartbeat");
        assert_eq!(env.source, "scheduler");
        assert_eq!(env.content, "HEARTBEAT");

        handle.abort();
    }
}
