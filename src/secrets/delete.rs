//! Deletes a secret. Secrets are immutable, so rotation is a delete plus a
//! fresh import under the same name.

use anyhow::Result;
use serde_json::json;
use turnkey_client::generated::immutable::activity::v1::DeleteSecretsIntent;

use super::{export::resolve_name, input::SecretRef};
use crate::{
    auth::ResolvedAuth,
    operations::{OperationOutput, submit_activity},
};

const COMMAND: &str = "secret.delete";

pub(super) async fn run(auth: ResolvedAuth, secret: SecretRef) -> Result<OperationOutput> {
    let secret_id = match secret {
        SecretRef::Id(id) => id,
        SecretRef::Name(name) => resolve_name(&auth, name).await?,
    };
    let submitted = submit_activity(
        &auth,
        COMMAND,
        "delete_secrets",
        "ACTIVITY_TYPE_DELETE_SECRETS",
        &DeleteSecretsIntent {
            secret_ids: vec![secret_id.to_string()],
        },
    )
    .await?;
    let response = submitted.into_data();
    let activity = &response["activity"];
    Ok(OperationOutput::result(
        COMMAND,
        json!({
            "secretId": secret_id,
            "activity": {
                "id": activity["id"],
                "status": activity["status"],
                "type": activity["type"],
                "result": activity["result"],
            },
        }),
    ))
}
