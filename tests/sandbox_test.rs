//! WASM Sandbox Tests

use demonclaw::sandbox::{Manifest, Sandbox};

#[test]
fn test_sandbox_creation() {
    let sandbox = Sandbox::new();
    assert!(sandbox.is_ok());
}

#[test]
fn test_manifest_creation() {
    let manifest = Manifest {
        can_http: vec!["10.0.0.0/8".to_string()],
        can_exec: false,
    };

    assert_eq!(manifest.can_http.len(), 1);
    assert!(!manifest.can_exec);
}

#[test]
fn test_empty_wasm_rejected() {
    let sandbox = Sandbox::new().unwrap();
    let manifest = Manifest {
        can_http: vec![],
        can_exec: false,
    };

    // Empty wasm should fail
    let result = sandbox.run_payload(&[], &manifest);
    assert!(result.is_err());
}
