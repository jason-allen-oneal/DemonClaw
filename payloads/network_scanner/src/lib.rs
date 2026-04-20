#![cfg_attr(target_arch = "wasm32", no_std)]

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "env")]
unsafe extern "C" {
    fn log(ptr: *const u8, len: usize);
    fn http_request(ptr: *const u8, len: usize) -> i32;
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn run() {
    let msg = b"[MODULE: network_scanner] STARTING: capability-driven subnet checks";
    let scan_target = b"https://scan.demonclaw.local/api/ports";

    unsafe {
        log(msg.as_ptr(), msg.len());

        let http_status = http_request(scan_target.as_ptr(), scan_target.len());
        if http_status == 0 {
            let ok = b"[MODULE: network_scanner] HTTP probe accepted by host policy";
            log(ok.as_ptr(), ok.len());
        } else {
            let denied = b"[MODULE: network_scanner] HTTP probe rejected by host policy";
            log(denied.as_ptr(), denied.len());
        }

        let results = b"[MODULE: network_scanner] COMPLETE: static phase finished";
        log(results.as_ptr(), results.len());
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[no_mangle]
pub extern "C" fn run() {
    let _ = "[MODULE: network_scanner] native build shim";
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
