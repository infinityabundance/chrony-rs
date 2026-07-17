//! Kernel-integration test for the real event-loop driver: a socketpair write must wake
//! `select()` and dispatch the registered file handler through the ported scheduler.

use chrony_rs_core::sched::SCH_FILE_INPUT;
use chrony_rs_io::driver::new_scheduler;
use chrony_rs_io::socket::Sockets;
use std::cell::RefCell;
use std::rc::Rc;

#[test]
fn select_driver_dispatches_a_real_socket_read() {
    let mut sck = Sockets::pre_initialise();
    sck.initialise(chrony_rs_core::socket::IPADDR_INET4);
    let (a, b) = sck.open_unix_socket_pair(0).expect("socketpair");

    let mut sched = new_scheduler();
    let got: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(Vec::new()));
    let got_h = got.clone();

    // Register a read handler on `a`; when it fires, drain the socket and quit the loop.
    sched.add_file_handler(
        a as usize,
        SCH_FILE_INPUT,
        Box::new(move |s, fd, event| {
            assert_eq!(event, SCH_FILE_INPUT);
            let mut buf = [0u8; 64];
            // SAFETY-free: use the same Sockets abstraction to read.
            let sockets = Sockets::default();
            let r = sockets.receive(fd, &mut buf, 0);
            if r > 0 {
                got_h.borrow_mut().extend_from_slice(&buf[..r as usize]);
            }
            s.quit_program();
        }),
    );

    // Write from the other end; select() should wake and dispatch.
    let payload = b"event-loop!";
    assert_eq!(sck.send(b, payload), payload.len() as isize);

    // Run the loop; the handler quits it after the read.
    sched.main_loop();

    assert_eq!(&*got.borrow(), payload);

    sck.close_socket(a);
    sck.close_socket(b);
}
