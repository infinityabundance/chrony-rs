//! Real OS I/O layer for chrony-rs — a faithful port of chrony's syscall-making modules
//! (`socket.c` and, over time, `ntp_io.c`, `sys_linux.c`, ...). The pure byte codecs and
//! discipline math live in `chrony-rs-core`; this crate owns the syscalls and is verified by
//! kernel-integration tests rather than differential-vs-C unit tests.
//!
//! Not a production time daemon — a forensic reconstruction for lab and replay use.

pub mod cmdmon;
pub mod config_loader;
pub mod driver;
pub mod key_io;
pub mod logging;
pub mod ntp_io;
pub mod privops;
pub mod rtc_linux_io;
pub mod shm_io;
pub mod sock_io;
pub mod socket;
