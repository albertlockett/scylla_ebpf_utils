#![no_std]

#[repr(C)]
pub struct FileEvent {
  pub filename: [u8; 400],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileEvent {}