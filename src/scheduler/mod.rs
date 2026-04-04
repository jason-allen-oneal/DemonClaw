use crate::types::Envelope;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::info;

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

        // First tick is usually immediate in tokio::time::interval
        let env = rx.recv().await.expect("Should receive heartbeat");
        assert_eq!(env.source, "scheduler");
        assert_eq!(env.content, "HEARTBEAT");
        
        handle.abort();
    }
}
