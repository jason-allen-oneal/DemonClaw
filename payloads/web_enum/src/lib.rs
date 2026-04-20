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
    let msg = b"[MODULE: web_enum] STARTING: enumerating high-value routes";
    let endpoint = b"https://target.demonclaw.local/.well-known/security.txt";

    unsafe {
        log(msg.as_ptr(), msg.len());

        let http_status = http_request(endpoint.as_ptr(), endpoint.len());
        if http_status == 0 {
            let ok = b"[MODULE: web_enum] outbound request approved";
            log(ok.as_ptr(), ok.len());
        } else {
            let denied = b"[MODULE: web_enum] outbound request denied";
            log(denied.as_ptr(), denied.len());
        }

        let results = b"[MODULE: web_enum] COMPLETE: static endpoint sweep done";
        log(results.as_ptr(), results.len());
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[no_mangle]
pub extern "C" fn run() {
    let _ = "[MODULE: web_enum] native build shim";
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
