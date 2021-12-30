#![no_std]

#[derive(Clone,Copy)]
#[repr(C)]
pub struct FileEvent {
  pub pid: u32
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileEvent {}