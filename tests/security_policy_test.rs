//! Security Policy Tests

use demonclaw::security::{SecurityPolicy, ToolLevel};

#[test]
fn test_default_policy() {
    let policy = SecurityPolicy::default();
    assert!(policy.allow_private_only);
    assert_eq!(policy.max_ports_per_scan, 256);
    assert_eq!(policy.max_tool_level, ToolLevel::Intrusive);
    assert!(policy.blocked_ports.contains(&22));
}

#[test]
fn test_validate_ports() {
    let policy = SecurityPolicy::default();

    // Valid ports
    let result = policy.validate_ports(&[80, 443, 8080]);
    assert!(result.is_ok());

    // Blocked port
    let result = policy.validate_ports(&[22]);
    assert!(result.is_err());

    // Empty ports
    let result = policy.validate_ports(&[]);
    assert!(result.is_err());
}

#[test]
fn test_tool_level_permitted() {
    // Intrusive allows all
    assert!(demonclaw::security::tool_level_permitted(ToolLevel::Intrusive, ToolLevel::Passive));
    assert!(demonclaw::security::tool_level_permitted(ToolLevel::Intrusive, ToolLevel::Active));
    assert!(demonclaw::security::tool_level_permitted(ToolLevel::Intrusive, ToolLevel::Intrusive));

    // Active blocks intrusive
    assert!(!demonclaw::security::tool_level_permitted(ToolLevel::Active, ToolLevel::Intrusive));
    assert!(demonclaw::security::tool_level_permitted(ToolLevel::Active, ToolLevel::Active));

    // Passive blocks active and intrusive
    assert!(!demonclaw::security::tool_level_permitted(ToolLevel::Passive, ToolLevel::Active));
    assert!(!demonclaw::security::tool_level_permitted(ToolLevel::Passive, ToolLevel::Intrusive));
}

#[test]
fn test_engagement_context() {
    let mut policy = SecurityPolicy::default();
    policy.require_engagement_context = true;

    // No engagement ID set
    assert!(policy.check_engagement_context("test").is_err());

    // Set engagement ID
    policy.engagement_id = Some("test-engagement".to_string());
    assert!(policy.check_engagement_context("test").is_ok());
}
