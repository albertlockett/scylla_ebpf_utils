#![no_std]
#![no_main]

use aya_bpf::{
  macros::kprobe,
  macros::{map},
  maps::PerfEventArray,
  programs::ProbeContext
};
use aya_bpf::helpers;
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
  let mut buf = [0u8; 64];
  let numreado = unsafe {
    helpers::bpf_probe_read_user_str(
      (*ctx.regs).rax as *const u8,
      &mut buf//.as_mut_ptr()// as *mut c_void,
    )
  }

  let numread = match numreado {
    Ok(v) => v as u32,
    Err(_e) => -1
  };

  let pid = helpers::bpf_get_current_pid_tgid() as u32;
  debug!(&ctx, "thing happened");
  let file_event = FileEvent{
    pid: pid,
    filename: buf,
    numread: numread
  };
  EVENTS.output(&ctx, &file_event, 0);
  Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
  unsafe { core::hint::unreachable_unchecked() }
}
