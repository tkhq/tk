use std::{
    net::TcpStream, os::unix::net::UnixStream, path::Path, process::Child, thread, time::Instant,
};

use super::{CHILD_READINESS_POLL_INTERVAL, CHILD_READINESS_TIMEOUT, Run};

impl Run {
    pub(crate) fn wait_for_child_socket(
        &self,
        child: &mut Option<Child>,
        path: &Path,
        process: &str,
        readiness: &str,
    ) {
        self.wait_for_child(child, process, readiness, || {
            UnixStream::connect(path).is_ok()
        });
    }

    pub(crate) fn wait_for_child_port(
        &self,
        child: &mut Option<Child>,
        port: u16,
        process: &str,
        readiness: &str,
    ) {
        self.wait_for_child(child, process, readiness, || {
            TcpStream::connect(("127.0.0.1", port)).is_ok()
        });
    }

    fn wait_for_child(
        &self,
        child: &mut Option<Child>,
        process: &str,
        readiness: &str,
        mut ready: impl FnMut() -> bool,
    ) {
        let deadline = Instant::now() + CHILD_READINESS_TIMEOUT;
        while !ready() {
            if child.as_mut().unwrap().try_wait().unwrap().is_some() {
                let output = child.take().unwrap().wait_with_output().unwrap();
                panic!(
                    "{process} exited before {readiness}: {}",
                    self.redact(&output.stderr)
                );
            }
            assert!(
                Instant::now() < deadline,
                "{process} did not finish {readiness}"
            );
            thread::sleep(CHILD_READINESS_POLL_INTERVAL);
        }
    }
}
