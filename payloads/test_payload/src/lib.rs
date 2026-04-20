#![cfg_attr(target_arch = "wasm32", no_std)]

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;

#[cfg(target_arch = "wasm32")]
unsafe extern "C" {
    fn log(ptr: *const u8, len: usize);
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn run() {
    let msg = b"Hello from DemonClaw WASM Sandbox (no_std)!";
    unsafe {
        log(msg.as_ptr(), msg.len());
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[unsafe(no_mangle)]
pub extern "C" fn run() {
    let _ = "Hello from DemonClaw native build shim";
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
