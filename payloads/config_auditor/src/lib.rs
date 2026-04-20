#![cfg_attr(target_arch = "wasm32", no_std)]

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "env")]
unsafe extern "C" {
    fn log(ptr: *const u8, len: usize);
    fn http_request(ptr: *const u8, len: usize) -> i32;
    fn exec_command(ptr: *const u8, len: usize) -> i32;
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn run() {
    let msg = b"[MODULE: config_auditor] STARTING: host configuration baseline audit";
    let policy_endpoint = b"https://config.demonclaw.local/policy/baseline";
    let command = b"echo config-audit-probe";

    unsafe {
        log(msg.as_ptr(), msg.len());

        let http_status = http_request(policy_endpoint.as_ptr(), policy_endpoint.len());
        if http_status == 0 {
            let ok = b"[MODULE: config_auditor] policy pull approved";
            log(ok.as_ptr(), ok.len());
        } else {
            let denied = b"[MODULE: config_auditor] policy pull denied";
            log(denied.as_ptr(), denied.len());
        }

        let command_status = exec_command(command.as_ptr(), command.len());
        if command_status >= 0 {
            let exec_ok = b"[MODULE: config_auditor] command execution bridge used";
            log(exec_ok.as_ptr(), exec_ok.len());
        } else {
            let exec_fail = b"[MODULE: config_auditor] command execution bridge blocked";
            log(exec_fail.as_ptr(), exec_fail.len());
        }

        let results = b"[MODULE: config_auditor] COMPLETE: baseline checks complete";
        log(results.as_ptr(), results.len());
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[no_mangle]
pub extern "C" fn run() {
    let _ = "[MODULE: config_auditor] native build shim";
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
