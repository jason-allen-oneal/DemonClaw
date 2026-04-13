//! Evidence Chain Tests

use demonclaw::evidence::{ChainVerification, EvidenceEvent};
use serde_json::json;
use uuid::Uuid;

#[test]
fn test_evidence_event_hash() {
    let event = EvidenceEvent::new(
        Uuid::new_v4(),
        None,
        "test.event",
        json!({"key": "value"}),
        Some(Uuid::new_v4()),
    );

    // Hash should be computed
    assert!(!event.hash.is_empty());
    assert_eq!(event.hash.len(), 64); // SHA-256 hex = 64 chars
}

#[test]
fn test_evidence_hash_verification() {
    let event = EvidenceEvent::new(
        Uuid::new_v4(),
        None,
        "test.event",
        json!({"key": "value"}),
        None,
    );

    // Hash should verify
    assert!(event.verify_hash());
}

#[test]
fn test_chain_linking() {
    let prev_hash = Some("abc123".to_string());
    let event = EvidenceEvent::new(
        Uuid::new_v4(),
        prev_hash.clone(),
        "test.event",
        json!({}),
        None,
    );

    assert_eq!(event.prev_hash, prev_hash);
}

#[test]
fn test_chain_verification_struct() {
    let verification = ChainVerification {
        total_events: 10,
        valid_events: 10,
        broken_links: vec![],
        hash_mismatches: vec![],
        is_valid: true,
    };

    assert!(verification.is_valid);
    assert_eq!(verification.total_events, verification.valid_events);
    assert!(verification.broken_links.is_empty());
}
