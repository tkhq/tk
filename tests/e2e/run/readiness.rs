use std::process::Child;
use std::thread;
use std::time::Instant;

use super::{CHILD_READINESS_POLL_INTERVAL, CHILD_READINESS_TIMEOUT, Run};

impl Run {
    pub(crate) fn wait_for_child(
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
