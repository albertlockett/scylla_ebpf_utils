#![no_std]

#[derive(Copy)]
#[repr(C)]
pub struct FileEvent {
  pub pid: i64
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileEvent {}