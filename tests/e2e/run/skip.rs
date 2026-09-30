use std::{env, fmt::Display};

pub(crate) fn skip(reason: impl Display) {
    assert!(env::var_os("CI").is_none(), "CI must not skip {reason}");
    eprintln!("skipping {reason}");
}
