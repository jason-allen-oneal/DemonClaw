//! TLS/crypto provider initialization.
//!
//! We intentionally build reqwest with `rustls-no-provider` to avoid pulling in
//! AWS-LC by default. That means we must install a rustls crypto provider at
//! runtime before any TLS client is constructed.

use std::sync::Once;

static INIT: Once = Once::new();

pub fn ensure_crypto_provider_installed() {
    INIT.call_once(|| {
        // Prefer the pure-Rust ring provider for portability.
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("failed to install rustls ring crypto provider");
    });
}

