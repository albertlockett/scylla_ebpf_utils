#![no_std]
#![no_main]

use aya_bpf::{
    macros::kprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::debug;
// use aya::BpfContext;

#[kprobe(name="scylla_tools_01")]
pub fn scylla_tools_01(ctx: ProbeContext) -> u32 {
    
    match unsafe { try_scylla_tools_01(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_scylla_tools_01(ctx: ProbeContext) -> Result<u32, u32> {
    debug!(&ctx, "try scylla tools 01 {}", ctx.pid());
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
