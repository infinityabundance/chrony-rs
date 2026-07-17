# I/O Layer Differential Testing

The `chrony-rs-io` crate contains 85 `unsafe` blocks for syscall wrappers
(socket operations, ioctls, adjtimex, etc.). These are NOT currently verified
by differential testing against real chronyd C output, unlike the core crate.

## Coverage

| Function | C equivalent | Tested? | Notes |
|----------|-------------|---------|-------|
| real_adjtimex | sys_linux.c adjtimex() | Integration | Tested by lab_daemon |
| send_message | ntp_io.c NIO_SendPacket | Integration | Used in lab_daemon |
| process_message | ntp_io.c NIO_ReceivePacket | Integration | Used in lab_daemon |
| read_drift_file | rtc_linux.c drift parsing | Unit | Port tested |
| write_drift_file | rtc_linux.c drift writing | Unit | Port tested |

## Plan

To differential-test the I/O layer, run chronyd -d -n with a known config,
capture its socket syscall trace via strace, and compare the syscall
sequence (args, return values) with chrony-rs executing the same config.
