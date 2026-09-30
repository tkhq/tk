//! Imports secrets by encrypting locally and submitting only ciphertext.

use std::{collections::BTreeMap, mem::take};

use anyhow::Result;
use serde_json::json;
use turnkey_client::ActivityResult;
use zeroize::Zeroizing;

use super::input::{SecretName, UniqueKeyValues, quorum_for};
use crate::{
    auth::{ResolvedAuth, build_turnkey_client},
    operations::OperationOutput,
};

pub(super) async fn run(
    auth: ResolvedAuth,
    name: SecretName,
    mut value: Zeroizing<String>,
    properties: UniqueKeyValues,
) -> Result<OperationOutput> {
    let quorum = quorum_for(auth.api_base_url.as_str())?;
    let ResolvedAuth {
        org_id,
        api_base_url,
        stamper,
        ..
    } = auth;
    let client = build_turnkey_client(stamper, &api_base_url)?;
    let properties: BTreeMap<String, String> = properties.into();
    let plaintext = take(&mut *value);
    let ActivityResult {
        result: secret_id,
        activity_id,
        status,
        app_proofs: _,
    } = client
        .import_secret(
            org_id.to_string(),
            Some(name.clone().into()),
            plaintext,
            properties,
            &quorum,
        )
        .await?;
    Ok(OperationOutput::result(
        "secret.import",
        json!({
            "secretId": secret_id,
            "name": name,
            "activity": {"id": activity_id, "status": status},
        }),
    ))
}
