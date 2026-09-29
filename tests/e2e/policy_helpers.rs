use crate::run::Run;

pub(crate) fn tag_consensus(tag: &str) -> String {
    format!("approvers.any(user, user.tags.contains('{tag}'))")
}

pub(crate) fn user_consensus(user_id: &str) -> String {
    format!("approvers.any(user, user.id == '{user_id}')")
}

pub(crate) fn allow_once(agent_tag: &str, human_tag: &str) -> String {
    format!(
        "{} && {}",
        tag_consensus(agent_tag),
        tag_consensus(human_tag)
    )
}

pub(crate) enum SignScope<'a> {
    Wallet(&'a str),
    PrivateKey(&'a str),
}

impl Run {
    pub(crate) fn deny_agent_credentials(&self, agent_tag: &str) {
        self.create_policy_from_flags(
            &self.name("agents-no-credentials"),
            "deny",
            &tag_consensus(agent_tag),
            "activity.resource == 'CREDENTIAL'",
        );
    }

    pub(crate) fn allow_user_signing(
        &self,
        name: &str,
        user_id: &str,
        scope: SignScope<'_>,
    ) -> String {
        let scope = match scope {
            SignScope::Wallet(id) => format!("wallet.id == '{id}'"),
            SignScope::PrivateKey(id) => format!("private_key.id == '{id}'"),
        };
        self.create_policy_from_flags(
            &self.name(name),
            "allow",
            &user_consensus(user_id),
            &format!("activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2' && {scope}"),
        )
    }

    pub(crate) fn allow_agent_export(&self, consensus: &str, level: &str) {
        self.create_policy_from_flags(
            &self.name(&format!("agents-export-{level}")),
            "allow",
            consensus,
            &format!(
                "activity.type == 'ACTIVITY_TYPE_EXPORT_SECRETS' && secret.static_properties['consensus'] == '{level}'"
            ),
        );
    }
}
