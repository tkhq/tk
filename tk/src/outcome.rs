//! The closed vocabulary of command outcomes.
//!
//! `Outcome` has exactly one variant per terminal shape, and the variant name
//! IS the wire `reason`: serde's internal tagging stamps
//! `"reason": "<variant_in_snake_case>"` onto every serialized outcome, so
//! the vocabulary cannot drift from the type and two shapes cannot share a
//! reason without rustc rejecting the duplicate variant name. Do not add
//! per-variant `#[serde(rename)]` overrides — that equality is the guarantee.
//!
//! Payload structs live in their own command modules. A command with multiple
//! terminal shapes (e.g. `ssh agent stop`) owns one variant per shape.
//!
//! `reason` strings are stable snake_case discriminators; renaming a variant
//! is a breaking change to the JSON contract.

use crate::commands::{agent, config, public_key};
use serde::Serialize;
use std::fmt::{self, Display, Formatter};

/// A machine-only terminal payload: JSON mode emits its `reason` record and
/// human mode prints nothing.
#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
pub struct MachineOnly {}

impl Display for MachineOnly {
    fn fmt(&self, _: &mut Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

/// One wide terminal outcome per command invocation (the wide-event model).
#[derive(Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum Outcome {
    ConfigValue(config::ConfigValue),
    ConfigValueSet(config::ConfigValueSet),
    ConfigListed(config::ConfigListed),
    PublicKeyPrinted(public_key::PublicKeyPrinted),
    GitSignCompleted(MachineOnly),
    AgentStarted(agent::AgentRunning),
    AgentStopped(agent::AgentStopped),
    AgentNotRunning(agent::AgentNotRunning),
    AgentStatusReport(agent::AgentRunning),
    AgentDaemonExited(MachineOnly),
}

impl Display for Outcome {
    /// Each payload renders itself; the terminal outcome just delegates. An
    /// empty rendering means the outcome is machine-only.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::ConfigValue(msg) => msg.fmt(f),
            Outcome::ConfigValueSet(msg) => msg.fmt(f),
            Outcome::ConfigListed(msg) => msg.fmt(f),
            Outcome::PublicKeyPrinted(msg) => msg.fmt(f),
            Outcome::GitSignCompleted(msg) => msg.fmt(f),
            Outcome::AgentStarted(msg) => msg.fmt(f),
            Outcome::AgentStopped(msg) => msg.fmt(f),
            Outcome::AgentNotRunning(msg) => msg.fmt(f),
            Outcome::AgentStatusReport(msg) => msg.fmt(f),
            Outcome::AgentDaemonExited(msg) => msg.fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    use crate::output::ErrorMessage;

    /// Reasons that live outside `Outcome`: the error envelope reasons.
    const NON_TERMINAL_REASONS: [&str; 2] = [
        ErrorMessage::RUNTIME_REASON,
        ErrorMessage::MISSING_INPUT_REASON,
    ];

    #[test]
    fn terminal_reasons_do_not_collide_with_non_terminal_reasons() {
        for outcome in Outcome::iter() {
            let value = serde_json::to_value(&outcome)
                .expect("every outcome payload must serialize as a JSON map");
            let reason = value["reason"]
                .as_str()
                .expect("every serialized outcome must carry a `reason` tag");

            assert!(
                !NON_TERMINAL_REASONS.contains(&reason),
                "terminal reason `{reason}` collides with a non-terminal reason"
            );
        }
    }

    #[test]
    fn reasons_are_snake_case() {
        let terminal_reasons = Outcome::iter().map(|outcome| {
            serde_json::to_value(outcome)
                .expect("every outcome payload must serialize as a JSON map")["reason"]
                .as_str()
                .expect("every serialized outcome must carry a `reason` tag")
                .to_string()
        });

        for reason in terminal_reasons.chain(NON_TERMINAL_REASONS.map(String::from)) {
            assert!(
                !reason.is_empty()
                    && reason.split('_').all(|word| {
                        !word.is_empty()
                            && word
                                .chars()
                                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                    }),
                "reason `{reason}` is not snake_case"
            );
        }
    }
}
