//! Resolves, decrypts, and delivers secret values. Pending exports persist a
//! recipient key so the same command can resume after approval.

use anyhow::{Context, Result};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, to_value};
use std::path::{Path, PathBuf};
use tracing::warn;
use turnkey_client::generated::immutable::activity::v1::{ExportSecretParams, ExportSecretsIntent};
use turnkey_client::generated::immutable::models::v1::{KeyValue, TransportEncryptionSuite};
use turnkey_client::generated::{
    ListSecretsRequest, ListSecretsResponse, external::options::v1::Pagination,
};
use turnkey_enclave_encrypt::{QuorumPublicKey, client::ExportClient};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::SecretOutput;
use super::input::{SecretRef, quorum_for};
use crate::auth::{
    ResolvedAuth, SecureCreateError, build_turnkey_client, secure_create, state_dir,
};
use crate::errors::{ActivityError, ActivityErrorKind, InvalidInput, Malformed, MissingResource};
use crate::operations::{OperationOutput, get_activity, observed, query, submit_activity};

const COMMAND: &str = "secret.export";
const NEXT_STEP: &str = "After approval, run the same export command again.";

pub(super) async fn list(
    auth: ResolvedAuth,
    limit: u32,
    cursor: Option<Uuid>,
) -> Result<OperationOutput> {
    let ResolvedAuth {
        org_id,
        api_base_url,
        stamper,
        ..
    } = auth;
    let client = build_turnkey_client(stamper, &api_base_url)?;
    let response = client
        .list_secrets(ListSecretsRequest {
            organization_id: org_id,
            pagination_options: Some(Pagination {
                limit: limit.to_string(),
                before: String::new(),
                after: cursor.map(|id| id.to_string()).unwrap_or_default(),
            }),
        })
        .await?;
    let next_cursor = (response.secrets.len() == limit as usize)
        .then(|| {
            response
                .secrets
                .last()
                .map(|secret| secret.secret_id.clone())
        })
        .flatten();
    Ok(OperationOutput::result(
        "secret.list",
        json!({"secrets": to_value(response.secrets)?, "nextCursor": next_cursor}),
    ))
}

/// Identifies the credential and endpoint that own a pending export.
struct Binding {
    organization_id: String,
    api_base_url: String,
    api_public_key: String,
}

impl Binding {
    /// Creates a binding with a normalized API base URL.
    fn of(auth: &ResolvedAuth) -> Self {
        Self {
            organization_id: auth.org_id.clone(),
            api_base_url: auth.api_base_url.trim_end_matches('/').to_owned(),
            api_public_key: hex::encode(auth.stamper.compressed_public_key()),
        }
    }
}

/// Persisted state for an export awaiting approval.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingExport {
    version: u32,
    organization_id: String,
    api_base_url: String,
    api_public_key: String,
    secret_id: Uuid,
    activity_id: String,
    target_public_key: String,
    key_material: Zeroizing<String>,
}

impl PendingExport {
    /// Returns the state path for this identity and secret.
    fn path(state: &Path, binding: &Binding, secret_id: Uuid) -> PathBuf {
        state
            .join("secrets/pending")
            .join(&binding.organization_id)
            .join(&binding.api_public_key)
            .join(format!("{secret_id}.json"))
    }

    /// Loads pending state, rejecting state owned by another binding.
    async fn load(path: &Path, binding: &Binding) -> Result<Option<Self>> {
        let bytes = match tokio::fs::read(path).await {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        let state: Self = serde_json::from_slice(&bytes).map_err(|error| {
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
        let mismatch = [
            (
                "organization",
                &state.organization_id,
                &binding.organization_id,
            ),
            ("API base URL", &state.api_base_url, &binding.api_base_url),
            ("credential", &state.api_public_key, &binding.api_public_key),
        ]
        .into_iter()
        .find(|(_, stored, current)| stored != current);
        if let Some((field, stored, current)) = mismatch {
            return Err(InvalidInput(format!(
                r#"pending export state {} belongs to a different {field} ({stored}, not {current}); resume it with the identity that started it"#,
                path.display()
            ))
            .into());
        }
        Ok(Some(state))
    }

    /// Creates state without replacing an existing file.
    async fn create(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let bytes = Zeroizing::new(serde_json::to_vec(self)?);
        secure_create(path, &bytes).await.map_err(|error| match error {
            SecureCreateError::Exists => InvalidInput(
                "another export of this secret is already pending; run the command again to continue it".into(),
            )
            .into(),
            SecureCreateError::Io(error) => anyhow::Error::new(error).context("write pending export state"),
        })
    }

    /// Rebuilds the recipient and verifies its target key.
    fn recipient(&self, quorum: &QuorumPublicKey) -> Result<ExportClient> {
        let ikm = Zeroizing::new(
            hex::decode(&*self.key_material)
                .map_err(|_| InvalidInput("pending export key material is not hex".into()))?,
        );
        if ikm.len() != 32 {
            return Err(InvalidInput("pending export key material must be 32 bytes".into()).into());
        }
        let recipient = ExportClient::dangerous_from_bytes(&*ikm, quorum);
        if recipient.target_public_key()? != self.target_public_key {
            return Err(InvalidInput(
                "pending export key material does not match its target key".into(),
            )
            .into());
        }
        Ok(recipient)
    }
}

async fn remove(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
    }
}

pub(super) async fn run(
    auth: ResolvedAuth,
    secret: SecretRef,
    out: Option<PathBuf>,
    context: Vec<KeyValue>,
) -> Result<SecretOutput> {
    // Both resolved before anything is submitted: an unknown API base URL
    // fails without stamping a request for that host, and an export never
    // starts without somewhere to keep the key that decrypts it.
    let quorum = quorum_for(&auth.api_base_url)?;
    let state_dir = state_dir()?;
    export(&state_dir, quorum, auth, secret, out, context).await
}

async fn export(
    state_dir: &Path,
    quorum: QuorumPublicKey,
    auth: ResolvedAuth,
    secret: SecretRef,
    out: Option<PathBuf>,
    context: Vec<KeyValue>,
) -> Result<SecretOutput> {
    let binding = Binding::of(&auth);
    let secret_id = match secret {
        SecretRef::Id(id) => id,
        SecretRef::Name(name) => resolve_name(&auth, &name).await?,
    };
    let path = PendingExport::path(state_dir, &binding, secret_id);

    // Continue the export this identity left awaiting approval.
    if let Some(state) = PendingExport::load(&path, &binding).await? {
        let fetched = get_activity(&auth, &state.activity_id).await?;
        // A rejected or failed export is over: clear the state so the next run
        // starts fresh. A failed removal must not hide why the export ended.
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
            return Ok(pending(record));
        }
        // Terminal, so a decrypt failure repeats on every later run: name the
        // state file the user has to delete to escape it.
        let value =
            decrypt(state.recipient(&quorum)?, &record, &auth.org_id).with_context(|| {
                format!(
                    "decrypt the completed export; delete {} to start a new export",
                    path.display()
                )
            })?;
        // Removed only once the value has reached the user, so a failed
        // delivery can still be retried against the same activity.
        let delivered = deliver(record, value, out).await?;
        remove(&path).await?;
        return Ok(delivered);
    }

    // Start a new export. The recipient key stays in memory until the API
    // names an activity that still needs approval, so a request the API
    // rejected or never answered leaves nothing behind to reconcile.
    let mut ikm = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *ikm);
    let recipient = ExportClient::dangerous_from_bytes(*ikm, &quorum);
    let target_public_key = recipient.target_public_key()?;
    let submitted = submit_activity(
        &auth,
        COMMAND,
        "export_secrets",
        "ACTIVITY_TYPE_EXPORT_SECRETS",
        &ExportSecretsIntent {
            secrets: vec![ExportSecretParams {
                secret_id: secret_id.to_string(),
                target_public_key: target_public_key.clone(),
                encryption_suite: TransportEncryptionSuite::EnclaveEncryptV1,
                request_context: context,
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
        let Binding {
            organization_id,
            api_base_url,
            api_public_key,
        } = binding;
        let state = PendingExport {
            version: 1,
            organization_id,
            api_base_url,
            api_public_key,
            secret_id,
            target_public_key,
            key_material: Zeroizing::new(hex::encode(ikm.as_slice())),
            activity_id: activity_id.clone(),
        };
        // The activity now exists and only this key can decrypt it, so a
        // failure here is unrecoverable: say which activity to abandon.
        state.create(&path).await.with_context(|| {
            format!(
                "save the recovery key for export activity {activity_id}; that export cannot be finished, so reject it and run a new export"
            )
        })?;
        return Ok(pending(record));
    }
    // Approved on submission, so the key was never needed beyond this process.
    let value = decrypt(recipient, &record, &auth.org_id)?;
    deliver(record, value, out).await
}

fn pending(record: OperationOutput) -> SecretOutput {
    let mut data = record.into_data();
    strip_result(&mut data);
    data["nextStep"] = NEXT_STEP.into();
    OperationOutput::result(COMMAND, data).into()
}

fn decrypt(
    mut recipient: ExportClient,
    record: &OperationOutput,
    org_id: &str,
) -> Result<Zeroizing<String>> {
    let bundle = record.data()["activity"]["result"]["exportSecretsResult"]["secretPayloads"]
        .as_array()
        .and_then(|payloads| match payloads.as_slice() {
            [serde_json::Value::String(bundle)] => Some(bundle.as_str()),
            _ => None,
        })
        .ok_or_else(|| {
            ActivityError::new(
                ActivityErrorKind::MalformedResponse,
                "export result did not contain exactly one payload",
            )
        })?;
    let value = Zeroizing::new(recipient.decrypt_secret(bundle, org_id)?);
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
fn strip_result(data: &mut serde_json::Value) {
    if let Some(activity) = data["activity"].as_object_mut() {
        activity.remove("result");
    }
}

/// Builds the export result while retaining ciphertext for decryption.
fn export_data(secret_id: Uuid, response: serde_json::Value) -> serde_json::Value {
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
                    SecureCreateError::Exists => anyhow::Error::new(InvalidInput(format!(
                        "refusing to overwrite {}",
                        path.display()
                    ))),
                    SecureCreateError::Io(error) => {
                        anyhow::Error::new(error).context(format!("write {}", path.display()))
                    }
                })?;
            data["out"] = path.to_string_lossy().into_owned().into();
            Ok(OperationOutput::result(COMMAND, data).into())
        }
        None => {
            data["value"] = value.as_str().into();
            Ok(SecretOutput::with_value(
                OperationOutput::result(COMMAND, data),
                value,
            ))
        }
    }
}

/// Resolves a unique secret name across all list pages.
async fn resolve_name(auth: &ResolvedAuth, name: &str) -> Result<Uuid> {
    let mut matches = Vec::new();
    let mut after = String::new();
    loop {
        let response = query(
            "/public/v1/query/list_secrets",
            &ListSecretsRequest {
                organization_id: auth.org_id.clone(),
                pagination_options: Some(Pagination {
                    limit: "100".into(),
                    before: String::new(),
                    after: after.clone(),
                }),
            },
            &auth.api_base_url,
            &auth.stamper,
        )
        .await?;
        let ListSecretsResponse { secrets: page } =
            serde_json::from_value(response).map_err(|error| {
                ActivityError::new(
                    ActivityErrorKind::MalformedResponse,
                    "list_secrets response was malformed",
                )
                .with_source(error)
            })?;
        let full = page.len() == 100;
        after = page
            .last()
            .map(|secret| secret.secret_id.clone())
            .unwrap_or_default();
        matches.extend(
            page.into_iter()
                .filter(|secret| secret.name.as_deref() == Some(name)),
        );
        if !full {
            break;
        }
    }
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

#[cfg(test)]
mod tests;
