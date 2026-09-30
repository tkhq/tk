//! Resolves, decrypts, and delivers secret values. Pending exports persist a
//! recipient key so the same command can resume after approval.

use std::{
    fmt::Display,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{Context, Error, Result};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, from_slice, json, to_value, to_vec};
use tokio::fs;
use tracing::warn;
use turnkey_client::generated::{
    ListSecretsRequest, ListSecretsResponse, SecretMetadata,
    external::options::v1::Pagination,
    immutable::{
        activity::v1::{ExportSecretParams, ExportSecretsIntent},
        models::v1::TransportEncryptionSuite,
    },
};
use turnkey_enclave_encrypt::{QuorumPublicKey, client::ExportClient};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    Listing, SecretOutput,
    input::{SecretName, SecretRef, UniqueKeyValues, quorum_for},
};
use crate::{
    auth::{ResolvedAuth, SecureCreateError, build_turnkey_client, secure_create, state_dir},
    errors::{ActivityError, ActivityErrorKind, InvalidInput, Malformed, MissingResource},
    operations::{OperationOutput, observed, query, query_activity, submit_activity},
};

const COMMAND: &str = "secret.export";
const NEXT_STEP: &str = "After approval, run the same export command again.";

pub(super) async fn list(
    auth: ResolvedAuth,
    limit: u32,
    listing: Listing,
) -> Result<OperationOutput> {
    let limit = limit as usize;
    let (secrets, next_cursor) = match listing {
        Listing::Filtered { after, selector } => {
            let mut secrets = list_all(&auth, after, Some(limit + 1), |secret| {
                selector.matches(secret)
            })
            .await?;
            let next_cursor = (secrets.len() > limit).then(|| {
                secrets.pop();
                secrets.last().map(|secret| secret.secret_id.clone())
            });
            (secrets, next_cursor.flatten())
        }
        Listing::Page(cursor) => {
            let ResolvedAuth {
                org_id,
                api_base_url,
                stamper,
                ..
            } = auth;
            let client = build_turnkey_client(stamper, &api_base_url)?;
            let ListSecretsResponse { secrets } = client
                .list_secrets(ListSecretsRequest {
                    organization_id: org_id.to_string(),
                    pagination_options: Some(Pagination {
                        limit: limit.to_string(),
                        before: String::new(),
                        after: cursor.map(|id| id.to_string()).unwrap_or_default(),
                    }),
                })
                .await?;
            let next_cursor = (secrets.len() == limit)
                .then(|| secrets.last().map(|secret| secret.secret_id.clone()))
                .flatten();
            (secrets, next_cursor)
        }
    };
    Ok(OperationOutput::result(
        "secret.list",
        json!({"secrets": to_value(secrets)?, "nextCursor": next_cursor}),
    ))
}

/// Identifies the credential and endpoint that own a pending export.
#[derive(Clone)]
pub(super) struct Binding {
    organization_id: Uuid,
    api_base_url: String,
    api_public_key: String,
}

impl Binding {
    pub(super) fn of(auth: &ResolvedAuth) -> Self {
        Self {
            organization_id: auth.org_id,
            api_base_url: auth.api_base_url.as_str().trim_end_matches('/').to_owned(),
            api_public_key: hex::encode(auth.stamper.compressed_public_key()),
        }
    }

    pub(super) fn pending_dir(&self, state: &Path) -> PathBuf {
        state
            .join("secrets/pending")
            .join(self.organization_id.to_string())
            .join(&self.api_public_key)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingExport {
    version: u32,
    organization_id: Uuid,
    api_base_url: String,
    api_public_key: String,
    secret_id: Uuid,
    activity_id: String,
    target_public_key: String,
    key_material: Zeroizing<String>,
}

impl PendingExport {
    fn path(dir: &Path, secret_id: Uuid) -> PathBuf {
        dir.join(format!("{secret_id}.json"))
    }

    async fn load(path: &Path, binding: &Binding) -> Result<Option<Self>> {
        let bytes = match fs::read(path).await {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        let state: Self = from_slice(&bytes).map_err(|error| {
            Malformed::new(
                format!(
                    "pending export state {} is malformed; delete it to start over",
                    path.display()
                ),
                error,
            )
        })?;
        if state.version != 1 {
            return Err(InvalidInput(format!(
                "pending export state {} has unsupported version {}",
                path.display(),
                state.version
            ))
            .into());
        }
        let mismatch: Option<(&str, &dyn Display, &dyn Display)> =
            if state.organization_id != binding.organization_id {
                Some((
                    "organization",
                    &state.organization_id,
                    &binding.organization_id,
                ))
            } else if state.api_base_url != binding.api_base_url {
                Some(("API base URL", &state.api_base_url, &binding.api_base_url))
            } else if state.api_public_key != binding.api_public_key {
                Some(("credential", &state.api_public_key, &binding.api_public_key))
            } else {
                None
            };
        if let Some((field, stored, current)) = mismatch {
            return Err(InvalidInput(format!(
                r#"pending export state {} belongs to a different {field} ({stored}, not {current}); resume it with the identity that started it"#,
                path.display()
            ))
            .into());
        }
        Ok(Some(state))
    }

    async fn create(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let bytes = Zeroizing::new(to_vec(self)?);
        secure_create(path, &bytes).await.map_err(|error| match error {
            SecureCreateError::Exists => InvalidInput(
                "another export of this secret is already pending; run the command again to continue it".into(),
            )
            .into(),
            SecureCreateError::Io(error) => Error::new(error).context("write pending export state"),
        })
    }

    fn recipient(&self, path: &Path, quorum: &QuorumPublicKey) -> Result<ExportClient> {
        let ikm = Zeroizing::new(hex::decode(&*self.key_material).map_err(|error| {
            Malformed::new(
                format!(
                    "pending export state {} has invalid key material; delete it to start over",
                    path.display()
                ),
                error,
            )
        })?);
        if ikm.len() != 32 {
            return Err(InvalidInput(format!(
                "pending export state {} key material must be 32 bytes",
                path.display()
            ))
            .into());
        }
        let recipient = ExportClient::dangerous_from_bytes(&*ikm, quorum);
        if recipient.target_public_key()? != self.target_public_key {
            return Err(InvalidInput(format!(
                "pending export state {} key material does not match its target key",
                path.display()
            ))
            .into());
        }
        Ok(recipient)
    }
}

pub(super) async fn list_all(
    auth: &ResolvedAuth,
    after: Option<Uuid>,
    cap: Option<usize>,
    mut keep: impl FnMut(&SecretMetadata) -> bool,
) -> Result<Vec<SecretMetadata>> {
    let mut secrets = Vec::new();
    let mut request = ListSecretsRequest {
        organization_id: auth.org_id.to_string(),
        pagination_options: Some(Pagination {
            limit: "100".into(),
            before: String::new(),
            after: after.map(|id| id.to_string()).unwrap_or_default(),
        }),
    };
    loop {
        let ListSecretsResponse { secrets: page } =
            query("/public/v1/query/list_secrets", &request, auth).await?;
        let full = page.len() == 100;
        if full
            && let Some(pagination) = &mut request.pagination_options
            && let Some(last) = page.last()
        {
            pagination.after = last.secret_id.clone();
        }
        let room = cap.map_or(usize::MAX, |cap| cap - secrets.len());
        secrets.extend(page.into_iter().filter(&mut keep).take(room));
        if !full || cap.is_some_and(|cap| secrets.len() >= cap) {
            break;
        }
    }
    Ok(secrets)
}

pub(super) async fn resolve_name(auth: &ResolvedAuth, name: SecretName) -> Result<Uuid> {
    let matches = list_all(auth, None, None, |secret| {
        secret.name.as_deref() == Some(name.as_str())
    })
    .await?;
    match matches.as_slice() {
        [] => Err(MissingResource::new("secret", name).into()),
        [one] => Uuid::parse_str(&one.secret_id).context("secret id from the API is not a UUID"),
        many => Err(InvalidInput(format!(
            "{} secrets are named {name}; export by id instead: {}",
            many.len(),
            many.iter()
                .map(|secret| secret.secret_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
        .into()),
    }
}

pub(super) async fn remove(path: &Path) -> Result<()> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
    }
}

pub(super) async fn run(
    auth: ResolvedAuth,
    secret: SecretRef,
    out: Option<PathBuf>,
    context: UniqueKeyValues,
) -> Result<SecretOutput> {
    let quorum = quorum_for(auth.api_base_url.as_str())?;
    let state_dir = state_dir()?;
    let secret_id = match secret {
        SecretRef::Id(id) => id,
        SecretRef::Name(name) => resolve_name(&auth, name).await?,
    };
    let binding = Binding::of(&auth);
    let pending_dir = binding.pending_dir(&state_dir);
    match export_value(&pending_dir, &quorum, binding, &auth, secret_id, context).await? {
        Exported::Decrypted {
            record,
            value,
            consumed,
        } => {
            let delivered = deliver(record, value, out).await?;
            if let Some(path) = consumed {
                remove(&path).await?;
            }
            Ok(delivered)
        }
        Exported::Pending(record) => Ok(record.into()),
    }
}

pub(super) enum Exported {
    Pending(OperationOutput),
    Decrypted {
        record: OperationOutput,
        value: Zeroizing<String>,
        consumed: Option<PathBuf>,
    },
}

pub(super) async fn export_value(
    pending_dir: &Path,
    quorum: &QuorumPublicKey,
    binding: Binding,
    auth: &ResolvedAuth,
    secret_id: Uuid,
    context: UniqueKeyValues,
) -> Result<Exported> {
    let path = PendingExport::path(pending_dir, secret_id);

    if let Some(state) = PendingExport::load(&path, &binding).await? {
        let fetched = query_activity(auth, &state.activity_id).await?;
        let record = match observed(COMMAND, export_data(secret_id, fetched)) {
            Ok(record) => record,
            Err(error) => {
                if let Err(remove_error) = remove(&path).await {
                    warn!(?remove_error, "pending export state was left behind");
                }
                return Err(error);
            }
        };
        if record.is_pending() {
            return Ok(Exported::Pending(pending(record)));
        }
        let recipient = state.recipient(&path, quorum)?;
        let value = decrypt(recipient, &record, auth.org_id).with_context(|| {
            format!(
                "decrypt the completed export; delete {} to start a new export",
                path.display()
            )
        })?;
        return Ok(Exported::Decrypted {
            record,
            value,
            consumed: Some(path),
        });
    }

    let mut ikm = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *ikm);
    let recipient = ExportClient::dangerous_from_bytes(*ikm, quorum);
    let target_public_key = recipient.target_public_key()?;
    let submitted = submit_activity(
        auth,
        COMMAND,
        "export_secrets",
        "ACTIVITY_TYPE_EXPORT_SECRETS",
        &ExportSecretsIntent {
            secrets: vec![ExportSecretParams {
                secret_id: secret_id.to_string(),
                target_public_key: target_public_key.clone(),
                encryption_suite: TransportEncryptionSuite::EnclaveEncryptV1,
                request_context: context.into(),
            }],
        },
    )
    .await?;
    let record = OperationOutput::result(COMMAND, export_data(secret_id, submitted.into_data()));
    if record.is_pending() {
        let activity_id = record.data()["activity"]["id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| {
                ActivityError::new(
                    ActivityErrorKind::MalformedResponse,
                    "pending export has no activity id",
                )
            })?;
        let state = PendingExport {
            version: 1,
            organization_id: binding.organization_id,
            api_base_url: binding.api_base_url,
            api_public_key: binding.api_public_key,
            secret_id,
            target_public_key,
            key_material: Zeroizing::new(hex::encode(ikm.as_slice())),
            activity_id,
        };
        state.create(&path).await.with_context(|| {
            format!(
                "save the recovery key for export activity {}; that export cannot be finished, so reject it and run a new export",
                state.activity_id
            )
        })?;
        return Ok(Exported::Pending(pending(record)));
    }
    let value = decrypt(recipient, &record, auth.org_id)?;
    Ok(Exported::Decrypted {
        record,
        value,
        consumed: None,
    })
}

fn pending(record: OperationOutput) -> OperationOutput {
    let mut data = record.into_data();
    strip_result(&mut data);
    data["nextStep"] = NEXT_STEP.into();
    OperationOutput::result(COMMAND, data)
}

fn decrypt(
    mut recipient: ExportClient,
    record: &OperationOutput,
    org_id: Uuid,
) -> Result<Zeroizing<String>> {
    let bundle = record.data()["activity"]["result"]["exportSecretsResult"]["secretPayloads"]
        .as_array()
        .and_then(|payloads| match payloads.as_slice() {
            [Value::String(bundle)] => Some(bundle.as_str()),
            _ => None,
        })
        .ok_or_else(|| {
            ActivityError::new(
                ActivityErrorKind::MalformedResponse,
                "export result did not contain exactly one payload",
            )
        })?;
    let value = Zeroizing::new(recipient.decrypt_secret(bundle, org_id.to_string())?);
    if value.is_empty() {
        return Err(ActivityError::new(
            ActivityErrorKind::MalformedResponse,
            "exported secret is empty",
        )
        .into());
    }
    Ok(value)
}

/// Removes ciphertext from command output.
fn strip_result(data: &mut Value) {
    if let Some(activity) = data["activity"].as_object_mut() {
        activity.remove("result");
    }
}

/// Builds the export result while retaining ciphertext for decryption.
fn export_data(secret_id: Uuid, response: Value) -> Value {
    let activity = &response["activity"];
    json!({
        "secretId": secret_id,
        "activity": {
            "id": activity["id"],
            "status": activity["status"],
            "type": activity["type"],
            "result": activity["result"],
        },
    })
}

async fn deliver(
    record: OperationOutput,
    value: Zeroizing<String>,
    out: Option<PathBuf>,
) -> Result<SecretOutput> {
    let mut data = record.into_data();
    strip_result(&mut data);
    match out {
        Some(path) => {
            secure_create(&path, value.as_bytes())
                .await
                .map_err(|error| match error {
                    SecureCreateError::Exists => Error::new(InvalidInput(format!(
                        "refusing to overwrite {}",
                        path.display()
                    ))),
                    SecureCreateError::Io(error) => {
                        Error::new(error).context(format!("write {}", path.display()))
                    }
                })?;
            data["out"] = path.to_string_lossy().into();
            Ok(OperationOutput::result(COMMAND, data).into())
        }
        None => {
            data["value"] = value.as_str().into();
            Ok(SecretOutput {
                record: OperationOutput::result(COMMAND, data),
                plain: Some(value),
            })
        }
    }
}

#[cfg(test)]
mod tests;
