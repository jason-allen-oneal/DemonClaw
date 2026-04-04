use std::fs;

use serde_json::json;

use demonclaw::{
    memory::MemoryManager,
    sandbox::{Manifest, Sandbox},
    scanner::Scanner,
};

fn test_db_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        // Default to the docker pgvector instance we brought up.
        "postgres://postgres:postgres@localhost:5433/demonclaw".to_string()
    })
}

fn unit_vec(v: f32, dim: usize) -> Vec<f32> {
    // Deterministic embedding generator for tests.
    let mut out = vec![0.0f32; dim];
    out[0] = v;
    out
}

#[tokio::test]
async fn memory_pgvector_insert_and_query() -> anyhow::Result<()> {
    let mm = MemoryManager::new(&test_db_url()).await?;
    mm.init_schema().await?;

    // Insert 2 chunks with obvious "direction" in dim 0.
    let run_id = uuid::Uuid::new_v4().to_string();

    let id_a = mm
        .insert_chunk(
            "alpha chunk",
            json!({"run_id": run_id, "label": "a"}),
            &unit_vec(1.0, 1536),
        )
        .await?;

    let id_b = mm
        .insert_chunk(
            "bravo chunk",
            json!({"run_id": run_id, "label": "b"}),
            &unit_vec(-1.0, 1536),
        )
        .await?;

    let matches = mm.query_similar_chunks(&unit_vec(0.9, 1536), 2).await?;
    anyhow::ensure!(!matches.is_empty(), "expected at least 1 match");

    // Top-1 should be closer to +1.0 than -1.0.
    anyhow::ensure!(matches[0].id == id_a, "expected top match to be id_a");

    // Sanity: ids exist.
    anyhow::ensure!(id_a != id_b);

    // Cleanup to keep the table small.
    sqlx::query("DELETE FROM memory_chunks WHERE metadata->>'run_id' = $1")
        .bind(run_id)
        .execute(&mm.pool)
        .await?;

    Ok(())
}

#[test]
fn scanner_accepts_known_payloads() -> anyhow::Result<()> {
    let scanner = Scanner::new();

    let payloads = [
        "test_payload",
        "network_scanner",
        "web_enum",
        "config_auditor",
    ];

    for p in payloads {
        let path = format!(
            "/home/rev/projects/DC/payloads/{}/target/wasm32-wasip1/release/{}.wasm",
            p, p
        );
        let wasm = fs::read(&path)?;
        scanner.scan(&wasm)?;
    }

    Ok(())
}

#[test]
fn sandbox_runs_payloads_with_expected_manifests() -> anyhow::Result<()> {
    let sandbox = Sandbox::new()?;

    let cases = [
        (
            "test_payload",
            Manifest {
                can_http: vec![],
                can_exec: false,
            },
        ),
        (
            "network_scanner",
            Manifest {
                can_http: vec!["scan.demonclaw.local".to_string()],
                can_exec: false,
            },
        ),
        (
            "web_enum",
            Manifest {
                can_http: vec!["target.demonclaw.local".to_string()],
                can_exec: false,
            },
        ),
        (
            "config_auditor",
            Manifest {
                can_http: vec!["config.demonclaw.local".to_string()],
                can_exec: true,
            },
        ),
    ];

    for (p, manifest) in cases {
        let path = format!(
            "/home/rev/projects/DC/payloads/{}/target/wasm32-wasip1/release/{}.wasm",
            p, p
        );
        let wasm = fs::read(&path)?;
        sandbox.run_payload(&wasm, &manifest)?;
    }

    Ok(())
}
