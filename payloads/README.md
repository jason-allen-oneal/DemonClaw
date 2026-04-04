# DemonClaw Payloads

WASM-based payloads for DemonClaw offensive operations.

## Building Payloads

All payloads compile to `wasm32-wasip1` target for WASI compatibility.

### Prerequisites

```bash
# Add WASM target
rustup target add wasm32-wasip1

# Install cargo-wasm (optional but recommended)
cargo install cargo-wasm
```

### Build Commands

```bash
# Build a specific payload
cd payloads/<payload_name>
cargo build --target wasm32-wasip1 --release

# Output location
ls target/wasm32-wasip1/release/<payload_name>.wasm
```

### Build All Payloads

```bash
# From DemonClaw root
for payload in payloads/*/; do
    (cd "$payload" && cargo build --target wasm32-wasip1 --release)
done
```

## Payload Structure

```
payloads/
├── <payload_name>/
│   ├── Cargo.toml          # Must specify crate-type = ["cdylib"]
│   └── src/
│       └── lib.rs          # Entry point: #[no_mangle] pub fn _start()
```

### Example Cargo.toml

```toml
[package]
name = "pb-recon"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["cdylib"]

[dependencies]
# No std dependencies - use core only or wasi imports
```

### Example Entry Point

```rust
#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn _start() {
    // Payload logic here
}
```

## Capability Manifests

Each payload requests capabilities via a manifest (JSON or TOML):

```json
{
  "payload_id": "pb-recon",
  "version": "0.1.0",
  "capabilities": {
    "can_http": ["10.0.0.0/8", "192.168.0.0/16"],
    "can_exec": false,
    "can_fs_read": ["/tmp"],
    "can_fs_write": []
  },
  "metadata": {
    "author": "BlueDot IT",
    "description": "Network reconnaissance scanner"
  }
}
```

## Security Notes

- All payloads are scanned by the **Payload Scanner** before execution
- Capabilities must be explicitly declared and approved
- Network access is restricted to allowlisted CIDRs/domains
- Process execution requires explicit `can_exec` capability
