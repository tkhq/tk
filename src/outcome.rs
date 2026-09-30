//! Outcome reasons; variant names are the stable `snake_case` JSON values.

use std::fmt::{self, Display, Formatter};

use serde::Serialize;

use crate::{
    gpg, skills,
    ssh::{self, agent},
};

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
    PublicKeyPrinted(ssh::PublicKeyPrinted),
    SshKeyCreated(ssh::RegisteredKey),
    SshKeyRegistered(ssh::RegisteredKey),
    SshKeyRemoved(ssh::RegisteredKey),
    SshKeysRegistered(ssh::RegisteredKeys),
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
    GpgAgentExited(MachineOnly),
    SkillsListed(skills::Listed),
    SkillsShown(skills::Shown),
    SkillsInstalled(skills::Installed),
}

impl Display for Outcome {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::PublicKeyPrinted(msg) => msg.fmt(f),
            Outcome::SshKeyCreated(msg) => write!(f, "created and registered {msg}"),
            Outcome::SshKeyRegistered(msg) => msg.fmt(f),
            Outcome::SshKeyRemoved(msg) => {
                write!(f, "removed SSH key {} from the registry", msg.fingerprint)?;
                msg.write_restart_hint(f)
            }
            Outcome::SshKeysRegistered(msg) => msg.fmt(f),
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
            Outcome::GpgAgentExited(msg) => msg.fmt(f),
            Outcome::SkillsListed(msg) => msg.fmt(f),
            Outcome::SkillsShown(msg) => msg.fmt(f),
            Outcome::SkillsInstalled(msg) => msg.fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use strum::IntoEnumIterator;

    use super::*;
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
