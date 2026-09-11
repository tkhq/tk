//! Imports secrets by encrypting locally and submitting only ciphertext.

use anyhow::Result;
use serde_json::json;
use std::collections::BTreeMap;
use turnkey_client::ActivityResult;
use turnkey_client::generated::immutable::models::v1::KeyValue;
use zeroize::Zeroizing;

use super::input::quorum_for;
use crate::auth::{ResolvedAuth, build_turnkey_client};
use crate::operations::OperationOutput;

pub(super) async fn run(
    auth: ResolvedAuth,
    name: String,
    mut value: Zeroizing<String>,
    properties: Vec<KeyValue>,
) -> Result<OperationOutput> {
    let quorum = quorum_for(&auth.api_base_url)?;
    let ResolvedAuth {
        org_id,
        api_base_url,
        stamper,
        ..
    } = auth;
    let client = build_turnkey_client(stamper, &api_base_url)?;
    let properties: BTreeMap<String, String> = properties
        .into_iter()
        .map(|KeyValue { key, value }| (key, value))
        .collect();
    // The SDK helper takes an owned String. Move the value out of the
    // zeroizing buffer rather than copy it.
    let plaintext = std::mem::take(&mut *value);
    let ActivityResult {
        result: secret_id,
        activity_id,
        status,
        app_proofs: _,
    } = client
        .import_secret(org_id, Some(name.clone()), plaintext, properties, &quorum)
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
