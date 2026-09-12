//! Outcome reasons; variant names are the stable snake_case JSON values.

use crate::commands::{agent, config, public_key};
use crate::gpg;
use serde::Serialize;
use std::fmt::{self, Display, Formatter};

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
pub struct MachineOnly {}

impl Display for MachineOnly {
    fn fmt(&self, _: &mut Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

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
    GpgKeyCreated(gpg::KeyRegistered),
    GpgKeyRegistered(gpg::KeyRegistered),
    GpgKeyRemoved(gpg::RegisteredKey),
    GpgKeysRegistered(gpg::KeysRegistered),
    GpgKeysListed(gpg::KeysListed),
    GpgPublicKeyExported(gpg::PublicKeyExported),
    GpgSignatureCreated(gpg::SignatureCreated),
}

impl Display for Outcome {
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
            Outcome::GpgKeyCreated(msg) => write!(f, "created and {msg}"),
            Outcome::GpgKeyRegistered(msg) => msg.fmt(f),
            Outcome::GpgKeyRemoved(msg) => write!(
                f,
                "removed OpenPGP key {} from the registry; its accounts stay in wallet {}",
                msg.fingerprint, msg.wallet_id
            ),
            Outcome::GpgKeysRegistered(msg) => msg.fmt(f),
            Outcome::GpgKeysListed(msg) => msg.fmt(f),
            Outcome::GpgPublicKeyExported(msg) => msg.fmt(f),
            Outcome::GpgSignatureCreated(msg) => msg.fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    use crate::output::ErrorMessage;

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
