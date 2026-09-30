//! Human durations for credential lifetimes.

use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use crate::errors::InvalidInput;

const MAX_SECONDS: u64 = 365 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ExpiresIn(u64);

impl ExpiresIn {
    pub(crate) fn seconds(self) -> u64 {
        self.0
    }
}

pub(crate) fn human_seconds(seconds: u64) -> String {
    for (unit, size) in [("d", 86_400), ("h", 3_600), ("m", 60)] {
        if seconds > 0 && seconds.is_multiple_of(size) {
            return format!("{}{unit}", seconds / size);
        }
    }
    format!("{seconds}s")
}

impl FromStr for ExpiresIn {
    type Err = InvalidInput;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        let (digits, unit) = match text.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
            Some((index, _)) => text.split_at(index),
            None => (text, "s"),
        };
        let multiplier = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 60 * 60,
            "d" => 24 * 60 * 60,
            _ => {
                return Err(InvalidInput(format!(
                    "duration {text:?} must end in s, m, h, or d"
                )));
            }
        };
        // The parse error only says the digits were not a number.
        #[allow(clippy::map_err_ignore)]
        let amount: u64 = digits.parse().map_err(|_| {
            InvalidInput(format!("duration {text:?} must start with a whole number"))
        })?;
        let seconds = amount
            .checked_mul(multiplier)
            .filter(|seconds| (1..=MAX_SECONDS).contains(seconds))
            .ok_or_else(|| {
                InvalidInput(format!("duration {text:?} must be between 1s and 365d"))
            })?;
        Ok(Self(seconds))
    }
}

impl Display for ExpiresIn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&human_seconds(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_unit_and_bare_seconds() {
        assert_eq!("7d".parse::<ExpiresIn>().unwrap().seconds(), 604_800);
        assert_eq!("48h".parse::<ExpiresIn>().unwrap().seconds(), 172_800);
        assert_eq!("30m".parse::<ExpiresIn>().unwrap().seconds(), 1_800);
        assert_eq!("90s".parse::<ExpiresIn>().unwrap().seconds(), 90);
        assert_eq!("90".parse::<ExpiresIn>().unwrap().seconds(), 90);
    }

    #[test]
    fn rejects_zero_negative_unknown_and_too_long() {
        for (bad, expected) in [
            ("0s", r#"duration "0s" must be between 1s and 365d"#),
            ("-1d", r#"duration "-1d" must end in s, m, h, or d"#),
            ("1w", r#"duration "1w" must end in s, m, h, or d"#),
            ("d", r#"duration "d" must start with a whole number"#),
            ("", r#"duration "" must start with a whole number"#),
            ("400d", r#"duration "400d" must be between 1s and 365d"#),
            ("1.5h", r#"duration "1.5h" must end in s, m, h, or d"#),
        ] {
            let InvalidInput(message) = bad.parse::<ExpiresIn>().unwrap_err();
            assert_eq!(message, expected, "{bad:?}");
        }
    }

    #[test]
    fn displays_the_largest_exact_unit() {
        assert_eq!("7d".parse::<ExpiresIn>().unwrap().to_string(), "7d");
        assert_eq!("36h".parse::<ExpiresIn>().unwrap().to_string(), "36h");
        assert_eq!("90s".parse::<ExpiresIn>().unwrap().to_string(), "90s");
        assert_eq!("120s".parse::<ExpiresIn>().unwrap().to_string(), "2m");
        assert_eq!(human_seconds(0), "0s");
    }
}
