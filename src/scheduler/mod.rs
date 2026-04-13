use crate::{config::ScheduledJobConfig, types::Envelope};
use chrono::{Datelike, Timelike, Utc};
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
                        if let Err(err) = enqueue_job(&tx, &job, "interval").await {
                            warn!("Scheduled job enqueue failed: {}", err);
                            break;
                        }
                    }
                } else if let Some(expr) = job.cron.clone() {
                    let parsed = match CronSchedule::parse(&expr) {
                        Ok(schedule) => schedule,
                        Err(err) => {
                            warn!("Invalid cron expression for job {}: {}", job.name, err);
                            return;
                        }
                    };
                    let mut ticker = interval(Duration::from_secs(1));
                    let mut last_fired_minute: Option<(i32, u32, u32, u32, u32)> = None;
                    info!("Scheduled cron job started: {} expr={}", job.name, expr);
                    loop {
                        ticker.tick().await;
                        let now = Utc::now();
                        let minute_key = (now.year(), now.month(), now.day(), now.hour(), now.minute());
                        if parsed.matches(now) && last_fired_minute != Some(minute_key) {
                            last_fired_minute = Some(minute_key);
                            if let Err(err) = enqueue_job(&tx, &job, "cron").await {
                                warn!("Cron job enqueue failed: {}", err);
                                break;
                            }
                        }
                    }
                }
            });
        }
    }
}

async fn enqueue_job(tx: &mpsc::Sender<Envelope>, job: &ScheduledJobConfig, schedule_kind: &str) -> Result<(), mpsc::error::SendError<Envelope>> {
    let mut env = Envelope::new(
        if job.source.is_empty() { "scheduler" } else { &job.source },
        &job.content,
    );
    env.metadata = serde_json::json!({
        "job_name": job.name,
        "schedule_kind": schedule_kind,
        "interval_secs": job.interval_secs,
        "cron": job.cron,
    });
    tx.send(env).await
}

#[derive(Debug, Clone)]
struct CronSchedule {
    minute: CronField,
    hour: CronField,
    day_of_month: CronField,
    month: CronField,
    day_of_week: CronField,
}

impl CronSchedule {
    fn parse(expr: &str) -> anyhow::Result<Self> {
        let parts: Vec<&str> = expr.split_whitespace().collect();
        anyhow::ensure!(parts.len() == 5, "cron must have 5 fields");
        Ok(Self {
            minute: CronField::parse(parts[0], 0, 59)?,
            hour: CronField::parse(parts[1], 0, 23)?,
            day_of_month: CronField::parse(parts[2], 1, 31)?,
            month: CronField::parse(parts[3], 1, 12)?,
            day_of_week: CronField::parse(parts[4], 0, 6)?,
        })
    }

    fn matches(&self, dt: chrono::DateTime<Utc>) -> bool {
        self.minute.matches(dt.minute())
            && self.hour.matches(dt.hour())
            && self.day_of_month.matches(dt.day())
            && self.month.matches(dt.month())
            && self.day_of_week.matches(dt.weekday().num_days_from_sunday())
    }
}

#[derive(Debug, Clone)]
enum CronField {
    Any,
    Exact(Vec<u32>),
}

impl CronField {
    fn parse(input: &str, min: u32, max: u32) -> anyhow::Result<Self> {
        if input == "*" {
            return Ok(Self::Any);
        }

        let mut values = Vec::new();
        for part in input.split(',') {
            if let Some((base, step)) = part.split_once('/') {
                let step: u32 = step.parse()?;
                anyhow::ensure!(step > 0, "cron step must be > 0");
                let (start, end) = if base == "*" {
                    (min, max)
                } else if let Some((a, b)) = base.split_once('-') {
                    (a.parse::<u32>()?, b.parse::<u32>()?)
                } else {
                    let v = base.parse::<u32>()?;
                    (v, max)
                };
                anyhow::ensure!(start >= min && end <= max && start <= end, "cron range out of bounds");
                let mut v = start;
                while v <= end {
                    values.push(v);
                    match v.checked_add(step) {
                        Some(next) if next > v => v = next,
                        _ => break,
                    }
                }
            } else if let Some((a, b)) = part.split_once('-') {
                let start = a.parse::<u32>()?;
                let end = b.parse::<u32>()?;
                anyhow::ensure!(start >= min && end <= max && start <= end, "cron range out of bounds");
                for v in start..=end {
                    values.push(v);
                }
            } else {
                let value = part.parse::<u32>()?;
                anyhow::ensure!(value >= min && value <= max, "cron value out of bounds");
                values.push(value);
            }
        }

        values.sort_unstable();
        values.dedup();
        Ok(Self::Exact(values))
    }

    fn matches(&self, value: u32) -> bool {
        match self {
            CronField::Any => true,
            CronField::Exact(values) => values.contains(&value),
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

    #[test]
    fn cron_parser_supports_basic_patterns() {
        let parsed = CronSchedule::parse("*/15 9-17 * * 1-5").expect("cron should parse");
        assert!(parsed.minute.matches(15));
        assert!(parsed.hour.matches(9));
        assert!(parsed.hour.matches(17));
        assert!(!parsed.hour.matches(18));
    }
}
