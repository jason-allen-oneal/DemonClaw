#![no_std]

use core::panic::PanicInfo;

unsafe extern "C" {
    fn log(ptr: *const u8, len: usize);
}

#[unsafe(no_mangle)]
pub extern "C" fn run() {
    let msg = b"Hello from DemonClaw WASM Sandbox (no_std)!";
    unsafe {
        log(msg.as_ptr(), msg.len());
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
