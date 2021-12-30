#![no_std]
#![no_main]

use aya_bpf::{
  macros::kprobe,
  macros::{map},
  programs::ProbeContext,
};
use aya_log_ebpf::debug;
use scylla_tools_01_common::FileEvent;

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<FileEvent> = PerfEventArray::<FileEvent>::with_max_entries(1024, 0);

#[kprobe(name="scylla_tools_01")]
pub fn scylla_tools_01(ctx: ProbeContext) -> u32 {
    
  match unsafe { try_scylla_tools_01(ctx) } {
    Ok(ret) => ret,
    Err(ret) => ret,
  }
}

unsafe fn try_scylla_tools_01(ctx: ProbeContext) -> Result<u32, u32> {
  /*
  let mut buf = [0u8; 400];
  unsafe {
    helpers::bpf_probe_read_user_str(
      (*ctx.regs).rax as *const u8,
      &mut buf//.as_mut_ptr()// as *mut c_void,
    );
  }

  let comm = core::str::from_utf8_unchecked(&buf[..]);
  debug!(&ctx, "try scylla tools 01 {}", comm);
  */
  Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
  unsafe { core::hint::unreachable_unchecked() }
}
