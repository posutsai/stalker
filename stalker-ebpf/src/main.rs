#![no_std]
#![no_main]
extern crate core;

use aya_bpf::{
    cty,
    helpers::{bpf_get_current_uid_gid, gen::bpf_probe_read_user_str},
    macros::{map, uprobe},
    maps::PerfEventArray,
    programs::ProbeContext,
};
use aya_log_ebpf::info;
use core::ffi::CStr;
use stalker_common::{SQLExecution, MAX_BUF_SIZE};

#[map]
static mut EVENTS: PerfEventArray<SQLExecution> = PerfEventArray::with_max_entries(1024, 0);

#[uprobe]
pub fn execute_sql_statement(ctx: ProbeContext) -> u32 {
    match try_execute_sql_statement(ctx) {
        Ok(return_code) => return_code,
        Err(return_code) => return_code,
    }
}

fn try_execute_sql_statement(ctx: ProbeContext) -> Result<u32, u32> {
    let mut sql = SQLExecution {
        statement: [0_u8; MAX_BUF_SIZE],
        len: 0,
    };
    let buf_ptr: *const u8 = ctx.arg(0).ok_or(0_u32)?;

    if buf_ptr.is_null() {
        return Ok(0);
    }

    unsafe {
        let len = bpf_probe_read_user_str(
            sql.statement.as_mut_ptr() as *mut cty::c_void,
            MAX_BUF_SIZE as u32,
            buf_ptr as *const cty::c_void,
        );
        sql.len = len;
        let _tgid = bpf_get_current_uid_gid();
        EVENTS.output(&ctx, &sql, 0);
    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
