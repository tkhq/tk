//! Encrypted Secrets transfer with durable, identity-bound export recovery.
use crate::{
    auth::{FileLock, ResolvedAuth},
    enclave::{SecretRecipient, encrypt_secret_with_bundle},
    errors::{ActivityError, ActivityErrorKind, Details, InvalidInput, UnexpectedHttpStatus},
    operations::{OperationOutput, envelope_at, query, submit_bytes, timestamp_ms},
};
use anyhow::{Context, Result, bail};
use clap::Subcommand;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_enclave_encrypt::QuorumPublicKey;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const SUITE: &str = "TRANSPORT_ENCRYPTION_SUITE_ENCLAVE_ENCRYPT_V1";
const MAX_SECRET_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    /// List metadata, one page at a time. Payloads are never returned.
    List {
        /// Page size.
        #[arg(long, default_value_t=50, value_parser=clap::value_parser!(u32).range(1..=100))]
        limit: u32,
        /// Secret ID to continue after (the previous page's nextCursor).
        #[arg(long)]
        cursor: Option<Uuid>,
    },
    /// Encrypt bytes from a file or stdin before submitting an import.
    Import {
        /// Name of the new secret.
        #[arg(long)]
        name: String,
        /// File holding the secret bytes, or - for stdin (1 MiB limit).
        #[arg(long)]
        input_file: PathBuf,
        /// JSON map of nonsecret, policy-visible string properties.
        #[arg(long)]
        static_properties_file: Option<PathBuf>,
        /// Continue a previously approved initialization without submitting another.
        #[arg(long)]
        init_activity_id: Option<Uuid>,
    },
    /// Export to a NEW protected file. Save recovery state before submitting.
    Export {
        /// ID of the secret to export.
        id: Uuid,
        /// New file for the decrypted secret (created 0600, never overwritten).
        #[arg(long)]
        output: PathBuf,
        /// New file for recovery state; keep it until the export completes.
        #[arg(long)]
        state_file: PathBuf,
        /// Seconds to wait for the export activity to complete.
        #[arg(long, default_value_t=60, value_parser=clap::value_parser!(u64).range(1..=3600))]
        timeout: u64,
    },
    /// Recover an export by inspecting its activity; never resubmits it.
    Resume {
        /// Recovery state file written by export.
        #[arg(long)]
        state_file: PathBuf,
        /// Seconds to wait for the export activity to complete.
        #[arg(long, default_value_t=60, value_parser=clap::value_parser!(u64).range(1..=3600))]
        timeout: u64,
    },
}

pub enum PreparedSecret {
    List {
        limit: u32,
        cursor: Option<Uuid>,
    },
    Import {
        name: String,
        plaintext: Zeroizing<Vec<u8>>,
        properties: std::collections::BTreeMap<String, String>,
        init_activity_id: Option<Uuid>,
    },
    Export {
        id: Uuid,
        output: PathBuf,
        state_file: PathBuf,
        timeout: u64,
    },
    Resume {
        state_file: PathBuf,
        timeout: u64,
    },
}

/// A local input check that clap cannot express.
fn check(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(InvalidInput(message.into()).into())
    }
}

/// The server responded without the fields this flow depends on.
fn malformed(message: &str) -> anyhow::Error {
    ActivityError::new(ActivityErrorKind::MalformedResponse, message).into()
}

impl SecretCommand {
    pub fn prepare(self) -> Result<PreparedSecret> {
        Ok(match self {
            Self::List { limit, cursor } => PreparedSecret::List { limit, cursor },
            Self::Import {
                name,
                input_file,
                static_properties_file,
                init_activity_id,
            } => {
                check(
                    !name.trim().is_empty() && name.len() <= 256,
                    "secret name must contain 1 to 256 bytes",
                )?;
                let properties = match static_properties_file {
                    Some(path) => {
                        serde_json::from_slice::<std::collections::BTreeMap<String, String>>(
                            &fs::read(path).context("read static properties")?,
                        )
                        .map_err(|_| {
                            InvalidInput(
                                "static properties must be a JSON object of nonsecret string values"
                                    .into(),
                            )
                        })?
                    }
                    None => Default::default(),
                };
                let mut plaintext = Zeroizing::new(Vec::new());
                if input_file.as_os_str() == "-" {
                    std::io::stdin()
                        .take(MAX_SECRET_BYTES + 1)
                        .read_to_end(&mut plaintext)
                        .context("read secret from stdin")?;
                } else {
                    File::open(input_file)
                        .context("open secret input")?
                        .take(MAX_SECRET_BYTES + 1)
                        .read_to_end(&mut plaintext)
                        .context("read secret input")?;
                }
                check(
                    plaintext.len() as u64 <= MAX_SECRET_BYTES,
                    "secret exceeds the 1 MiB CLI input limit",
                )?;
                PreparedSecret::Import {
                    name,
                    plaintext,
                    properties,
                    init_activity_id,
                }
            }
            Self::Export {
                id,
                output,
                state_file,
                timeout,
            } => {
                let output = new_path(output)?;
                let state_file = new_path(state_file)?;
                check(
                    output != state_file,
                    "output and recovery state must be different files",
                )?;
                PreparedSecret::Export {
                    id,
                    output,
                    state_file,
                    timeout,
                }
            }
            Self::Resume {
                state_file,
                timeout,
            } => {
                let state_file = absolute_path(state_file)?;
                ExportState::read(&state_file)?;
                PreparedSecret::Resume {
                    state_file,
                    timeout,
                }
            }
        })
    }
}

fn absolute_path(path: PathBuf) -> Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| InvalidInput("destination must name a file".into()))?;
    check(
        path.as_os_str() != "-",
        "stdout is not a protected destination",
    )?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(parent
        .canonicalize()
        .context("resolve destination directory")?
        .join(name))
}
fn new_path(path: PathBuf) -> Result<PathBuf> {
    let path = absolute_path(path)?;
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(path),
        Err(e) => Err(e).context("inspect destination"),
        Ok(_) => Err(InvalidInput("destination already exists; choose a new file".into()).into()),
    }
}

/// Persisted schemas are private credential material, never command output.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportState {
    version: u8,
    organization_id: Uuid,
    api_base_url: String,
    identity_public_key: String,
    secret_id: Uuid,
    target_public_key: String,
    proposal: String,
    fingerprint: String,
    output: PathBuf,
    key_material: Option<String>,
    activity_id: Option<String>,
    completed: bool,
}
impl Drop for ExportState {
    fn drop(&mut self) {
        if let Some(key) = &mut self.key_material {
            key.zeroize();
        }
    }
}
impl ExportState {
    fn read(path: &Path) -> Result<Self> {
        let encoded = read_private(path, 1024 * 1024)?;
        // Never echo the state file: it holds recovery key material.
        let state: Self = serde_json::from_slice(&encoded)
            .map_err(|_| InvalidInput("invalid recovery state schema".into()))?;
        check(state.version == 1, "unsupported recovery state version")?;
        check(
            state.output.is_absolute(),
            "recovery output path must be absolute",
        )?;
        check(
            state.fingerprint == fingerprint(&state.proposal),
            "recovery proposal fingerprint mismatch",
        )?;
        let proposal: Value = serde_json::from_str(&state.proposal)
            .map_err(|_| InvalidInput("invalid recovery proposal".into()))?;
        let expected = envelope_at(
            "ACTIVITY_TYPE_EXPORT_SECRETS",
            &state.organization_id.to_string(),
            proposal
                .get("timestampMs")
                .and_then(Value::as_str)
                .ok_or_else(|| InvalidInput("missing proposal timestamp".into()))?,
            &json!({"secrets":[{"secretId":state.secret_id,"targetPublicKey":state.target_public_key,"encryptionSuite":SUITE}]}),
        );
        check(
            proposal == expected,
            "recovery proposal does not match its context",
        )?;
        check(
            state.completed == state.key_material.is_none(),
            "invalid recovery completion state",
        )?;
        Ok(state)
    }
    fn save(&self, path: &Path, create: bool) -> Result<()> {
        #[cfg(not(unix))]
        bail!("protected Secrets files currently require a Unix filesystem");
        let encoded = Zeroizing::new(serde_json::to_vec(self).context("encode recovery state")?);
        write_durable(path, &encoded, !create)
    }

    /// Recovery details for error records: where the state lives and what it
    /// proposes, never its key material.
    fn details(&self, path: &Path, activity: Option<&Value>) -> Value {
        let mut data = json!({"secretId":self.secret_id,"stateFile":path,"output":self.output,"fingerprint":self.fingerprint,"completed":self.completed});
        if let Some(activity) = activity {
            data["activity"] = json!({"id":activity["id"],"status":activity["status"]});
        }
        data
    }
}

/// Writes bytes durably: an fsynced temp file in the destination directory,
/// renamed into place (never replacing an existing file unless `replace`),
/// then a directory fsync.
///
/// This module keeps its protected-file I/O synchronous on purpose: the
/// fsync/rename sequence and the `O_NOFOLLOW` permission checks are short and
/// must not interleave with other work on the same paths.
fn write_durable(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    let parent = path.parent().context("destination directory missing")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).context("create temporary file")?;
    temporary.write_all(bytes).context("write bytes")?;
    temporary.as_file().sync_all().context("persist bytes")?;
    if replace {
        temporary
            .persist(path)
            .map_err(|error| error.error)
            .context("cannot replace destination")?;
    } else {
        temporary
            .persist_noclobber(path)
            .map_err(|error| error.error)
            .context("destination already exists or cannot be created")?;
    }
    File::open(parent)?.sync_all().context("persist directory")
}

fn fingerprint(body: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(body.as_bytes())))
}
/// A freshly timestamped activity envelope.
fn envelope(kind: &str, org: &str, parameters: Value) -> Result<Value> {
    Ok(envelope_at(kind, org, &timestamp_ms()?, &parameters))
}

/// The metadata subset of the Secrets list response. Decoding through these
/// types strips every unexpected field, so encrypted payloads or plaintext can
/// never ride along into command output. Mirrors the generated
/// `ListSecretsResponse` in newer `turnkey_client` revisions.
#[derive(Deserialize)]
struct ListSecretsResponse {
    #[serde(default)]
    secrets: Vec<SecretMetadata>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretMetadata {
    secret_id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    static_properties: Vec<KeyValue>,
    #[serde(default)]
    created_at_unix_ms: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct KeyValue {
    #[serde(default)]
    key: String,
    #[serde(default)]
    value: String,
}

/// Maps an activity status to a terminal outcome: `Ok(true)` when completed,
/// `Ok(false)` while pending, and an error carrying the activity identity
/// when it was rejected, failed, or unrecognized.
fn activity_terminal(activity: &Value, denied: &str) -> Result<bool> {
    let identity = json!({"id":activity["id"],"status":activity["status"]});
    match activity["status"].as_str() {
        Some("ACTIVITY_STATUS_COMPLETED") => Ok(true),
        Some(
            "ACTIVITY_STATUS_CREATED"
            | "ACTIVITY_STATUS_PENDING"
            | "ACTIVITY_STATUS_CONSENSUS_NEEDED"
            | "ACTIVITY_STATUS_AUTHENTICATORS_NEEDED",
        ) => Ok(false),
        Some("ACTIVITY_STATUS_REJECTED" | "ACTIVITY_STATUS_FAILED") => {
            Err(ActivityError::new(ActivityErrorKind::NotCompleted, denied)
                .with_activity(identity)
                .into())
        }
        _ => Err(ActivityError::new(
            ActivityErrorKind::MalformedResponse,
            "unrecognized activity status; inspect the activity before continuing",
        )
        .with_activity(identity)
        .into()),
    }
}

impl PreparedSecret {
    pub async fn run(self, auth: ResolvedAuth) -> Result<OperationOutput> {
        self.run_with_key(
            &auth.org_id,
            &auth.api_base_url,
            &auth.stamper,
            &QuorumPublicKey::production_signer(),
        )
        .await
    }
    async fn run_with_key(
        self,
        org: &str,
        endpoint: &str,
        stamper: &TurnkeyP256ApiKey,
        quorum: &QuorumPublicKey,
    ) -> Result<OperationOutput> {
        match self {
            Self::List { limit, cursor } => {
                let response = query("/public/v1/query/list_secrets", &json!({"organizationId":org,"paginationOptions":{"limit":limit.to_string(),"after":cursor.map(|v|v.to_string()).unwrap_or_default()}}), endpoint, stamper).await?;
                let decoded: ListSecretsResponse = serde_json::from_value(response)
                    .map_err(|_| malformed("invalid Secrets metadata response"))?;
                let next = if decoded.secrets.len() == limit as usize {
                    decoded.secrets.last().map(|s| s.secret_id.clone())
                } else {
                    None
                };
                Ok(OperationOutput::result(
                    "secret.list",
                    json!({"items":decoded.secrets,"nextCursor":next}),
                ))
            }
            Self::Import {
                name,
                plaintext,
                properties,
                init_activity_id,
            } => {
                let init_body = serde_json::to_string(&envelope(
                    "ACTIVITY_TYPE_INIT_IMPORT_SECRETS",
                    org,
                    json!({"encryptionSuite":SUITE,"numSecrets":1}),
                )?)?;
                let init_fingerprint = fingerprint(&init_body);
                let init_details = json!({
                    "phase": "init-import",
                    "fingerprint": init_activity_id.is_none().then_some(init_fingerprint.as_str()),
                });
                let init = if let Some(id) = init_activity_id {
                    query(
                        "/public/v1/query/get_activity",
                        &json!({"organizationId":org,"activityId":id}),
                        endpoint,
                        stamper,
                    )
                    .await
                } else {
                    submit_bytes(
                        "/public/v1/submit/init_import_secrets",
                        init_body,
                        endpoint,
                        stamper,
                    )
                    .await
                }
                .map_err(|error| {
                    error.context(Details::new(
                        "secret import initialization failed",
                        init_details.clone(),
                    ))
                })?;
                let activity = init
                    .get("activity")
                    .ok_or_else(|| malformed("missing initialization activity"))?;
                if activity["organizationId"] != org
                    || activity["type"] != "ACTIVITY_TYPE_INIT_IMPORT_SECRETS"
                {
                    return Err(malformed("initialization activity context mismatch"));
                }
                if let Some(id) = init_activity_id {
                    if activity["id"] != id.to_string() {
                        return Err(malformed("initialization activity ID mismatch"));
                    }
                    let intent = activity
                        .pointer("/intent/initImportSecretsIntent")
                        .ok_or_else(|| malformed("missing initialization intent"))?;
                    let num_secrets = &intent["numSecrets"];
                    if intent["encryptionSuite"] != SUITE
                        || (*num_secrets != 1 && *num_secrets != "1")
                    {
                        return Err(malformed("initialization intent mismatch"));
                    }
                } else if activity["fingerprint"] != init_fingerprint {
                    return Err(malformed("initialization fingerprint mismatch"));
                }
                let completed = activity_terminal(
                    activity,
                    "initialization was denied or failed; no secret was imported",
                )
                .map_err(|error| {
                    error.context(Details::new(
                        "secret import initialization did not complete",
                        init_details.clone(),
                    ))
                })?;
                if !completed {
                    return Ok(OperationOutput::result(
                        "secret.import",
                        json!({"phase":"init-import","activity":{"id":activity["id"],"status":activity["status"]},"nextStep":"After approval, repeat import with --init-activity-id and the original input file."}),
                    ));
                }
                let targets = activity
                    .pointer("/result/initImportSecretsResult/enclaveTargetMessages")
                    .and_then(Value::as_array)
                    .ok_or_else(|| malformed("missing initialization target bundle"))?;
                let [bundle] = targets.as_slice() else {
                    return Err(malformed("expected exactly one initialization target"));
                };
                let bundle = bundle
                    .as_str()
                    .ok_or_else(|| malformed("invalid initialization target bundle"))?;
                let (payload, target) = encrypt_secret_with_bundle(quorum, &plaintext, bundle, org)
                    .context("verify initialization bundle and encrypt secret")?;
                let body = serde_json::to_string(&envelope(
                    "ACTIVITY_TYPE_IMPORT_SECRETS",
                    org,
                    json!({"secrets":[{"name":name,"secretPayload":payload,"targetPublicKey":target,"encryptionSuite":SUITE,"staticProperties":properties.into_iter().map(|(key,value)|json!({"key":key,"value":value})).collect::<Vec<_>>()}]}),
                )?)?;
                let expected_fingerprint = fingerprint(&body);
                let import_details = json!({"phase":"import","fingerprint":expected_fingerprint});
                let result =
                    submit_bytes("/public/v1/submit/import_secrets", body, endpoint, stamper)
                        .await
                        .map_err(|error| {
                            error.context(Details::new(
                                "secret import submission failed",
                                import_details.clone(),
                            ))
                        })?;
                let activity = result
                    .get("activity")
                    .ok_or_else(|| malformed("missing import activity"))?;
                if activity["organizationId"] != org
                    || activity["type"] != "ACTIVITY_TYPE_IMPORT_SECRETS"
                    || activity["fingerprint"] != expected_fingerprint
                {
                    return Err(malformed("import activity context mismatch"));
                }
                let completed = activity_terminal(
                    activity,
                    "import was denied or failed; no secret was imported",
                )
                .map_err(|error| {
                    error.context(Details::new(
                        "secret import did not complete",
                        import_details.clone(),
                    ))
                })?;
                let ids = activity.pointer("/result/importSecretsResult/secretIds");
                if completed
                    && !ids.and_then(Value::as_array).is_some_and(|v| {
                        v.len() == 1 && v[0].as_str().is_some_and(|s| Uuid::parse_str(s).is_ok())
                    })
                {
                    return Err(malformed("completed import omitted secret ID"));
                }
                Ok(OperationOutput::result(
                    "secret.import",
                    json!({"phase":"import","secretIds":ids,"activity":{"id":activity["id"],"status":activity["status"]}}),
                ))
            }
            Self::Export {
                id,
                output,
                state_file,
                timeout,
            } => {
                let mut ikm = Zeroizing::new([0u8; 32]);
                OsRng.fill_bytes(ikm.as_mut());
                let target_public_key =
                    SecretRecipient::from_ikm(ikm.as_ref(), quorum)?.target_public_key()?;
                let proposal = serde_json::to_string(&envelope(
                    "ACTIVITY_TYPE_EXPORT_SECRETS",
                    org,
                    json!({"secrets":[{"secretId":id,"targetPublicKey":target_public_key,"encryptionSuite":SUITE}]}),
                )?)?;
                let mut state = ExportState {
                    version: 1,
                    organization_id: Uuid::parse_str(org)?,
                    api_base_url: endpoint.to_owned(),
                    identity_public_key: hex::encode(stamper.compressed_public_key()),
                    secret_id: id,
                    target_public_key,
                    fingerprint: fingerprint(&proposal),
                    proposal,
                    output,
                    key_material: Some(hex::encode(ikm.as_ref())),
                    activity_id: None,
                    completed: false,
                };
                let _lock = state_lock(&state_file).await?;
                state.save(&state_file, true)?;
                let response = submit_bytes(
                    "/public/v1/submit/export_secrets",
                    state.proposal.clone(),
                    endpoint,
                    stamper,
                )
                .await;
                let response = match response {
                    Ok(response) => response,
                    // A definitive client rejection created no activity, so
                    // there is nothing to recover: drop the state and start over.
                    Err(error)
                        if error
                            .downcast_ref::<UnexpectedHttpStatus>()
                            .is_some_and(|http| (400..500).contains(&http.status)) =>
                    {
                        drop(_lock);
                        let _ = fs::remove_file(&state_file);
                        return Err(error.context(Details::new(
                            "export was not created; fix the request and start a new export",
                            json!({"secretId": id, "phase": "submit"}),
                        )));
                    }
                    // Anything else is ambiguous: recover only by observation, never replay.
                    Err(error) => {
                        return Err(error.context(Details::new(
                            "export submission did not complete; resume with the saved state file",
                            state.details(&state_file, None),
                        )));
                    }
                };
                let Some(activity) = response.get("activity") else {
                    return Err(anyhow::Error::new(ActivityError::new(
                        ActivityErrorKind::SubmissionUnknown,
                        "response omitted activity identity; resume with the saved state file",
                    ))
                    .context(Details::new(
                        "export submission outcome is unknown",
                        state.details(&state_file, None),
                    )));
                };
                bind_activity(&mut state, activity)?;
                state.save(&state_file, false)?;
                recover(
                    state,
                    state_file,
                    timeout,
                    endpoint,
                    stamper,
                    quorum,
                    "secret.export",
                )
                .await
            }
            Self::Resume {
                state_file,
                timeout,
            } => {
                let _lock = state_lock(&state_file).await?;
                let state = ExportState::read(&state_file)?;
                check(
                    state.organization_id.to_string() == org,
                    "recovery requires the organization that started the export",
                )?;
                check(
                    state.api_base_url == endpoint,
                    "recovery requires the API endpoint that started the export",
                )?;
                check(
                    state.identity_public_key == hex::encode(stamper.compressed_public_key()),
                    "recovery requires the credential that started the export",
                )?;
                recover(
                    state,
                    state_file,
                    timeout,
                    endpoint,
                    stamper,
                    quorum,
                    "secret.resume",
                )
                .await
            }
        }
    }
}

fn state_output(
    state: &ExportState,
    path: &Path,
    command: &'static str,
    activity: Option<&Value>,
) -> OperationOutput {
    OperationOutput::result(command, state.details(path, activity))
}
fn bind_activity(state: &mut ExportState, activity: &Value) -> Result<()> {
    let id = activity
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| malformed("missing export activity ID"))?;
    if activity["organizationId"] != state.organization_id.to_string()
        || activity["type"] != "ACTIVITY_TYPE_EXPORT_SECRETS"
        || activity["fingerprint"] != state.fingerprint
    {
        return Err(malformed(
            "export activity does not match persisted proposal",
        ));
    }
    if let Some(expected) = &state.activity_id
        && expected != id
    {
        return Err(malformed("export activity ID changed"));
    }
    state.activity_id = Some(id.to_owned());
    Ok(())
}

/// Drives an export to completion purely by observation. Every failure after
/// the state file exists carries its recovery details.
#[allow(clippy::too_many_arguments)]
async fn recover(
    mut state: ExportState,
    state_file: PathBuf,
    timeout: u64,
    endpoint: &str,
    stamper: &TurnkeyP256ApiKey,
    quorum: &QuorumPublicKey,
    command: &'static str,
) -> Result<OperationOutput> {
    if state.completed {
        private_file(&state.output).context("completed export output is missing or no longer protected; recovery key was already removed")?;
        return Ok(state_output(&state, &state_file, command, None));
    }
    let ikm = Zeroizing::new(
        hex::decode(
            state
                .key_material
                .as_ref()
                .ok_or_else(|| InvalidInput("missing recovery key".into()))?,
        )
        .map_err(|_| InvalidInput("invalid recovery key".into()))?,
    );
    let mut decryptor = SecretRecipient::from_ikm(&ikm, quorum)?;
    check(
        decryptor.target_public_key()? == state.target_public_key,
        "recovery key does not match export target",
    )?;
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let mut last: Option<Value> = None;
    loop {
        let step = recovery_step(
            &mut state,
            &state_file,
            endpoint,
            stamper,
            &mut decryptor,
            deadline,
        )
        .await;
        let retained = Details::new(
            "export recovery state is retained",
            state.details(&state_file, last.as_ref()),
        );
        match step.map_err(|error| error.context(retained))? {
            Step::Completed(activity) => {
                return Ok(state_output(&state, &state_file, command, Some(&activity)));
            }
            Step::Pending(activity) => last = Some(activity),
            Step::Bound | Step::NotFound => {}
        }
        if Instant::now() >= deadline {
            let (kind, message) = match &last {
                Some(_) => (
                    ActivityErrorKind::WaitTimeout,
                    "export is not complete; run secret resume with the saved state file, no submission was replayed",
                ),
                // The activity was never observed, so the submission outcome is
                // still unknown rather than merely slow.
                None => (
                    ActivityErrorKind::SubmissionUnknown,
                    "export activity was not found; run secret resume with the saved state file, no submission was replayed",
                ),
            };
            let identity = last
                .as_ref()
                .map(|activity| json!({"id":activity["id"],"status":activity["status"]}))
                .unwrap_or_else(|| json!({"id": state.activity_id, "status": null}));
            return Err(anyhow::Error::new(
                ActivityError::new(kind, message).with_activity(identity),
            )
            .context(Details::new(
                "export recovery state is retained",
                state.details(&state_file, last.as_ref()),
            )));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// One observation of the export activity.
enum Step {
    /// The output is durable and the recovery key is scrubbed.
    Completed(Value),
    /// The activity exists but has not finished.
    Pending(Value),
    /// The activity was discovered by fingerprint and bound; the next step
    /// fetches it in full.
    Bound,
    /// No activity matched the persisted fingerprint yet.
    NotFound,
}

async fn recovery_step(
    state: &mut ExportState,
    state_file: &Path,
    endpoint: &str,
    stamper: &TurnkeyP256ApiKey,
    decryptor: &mut SecretRecipient,
    deadline: Instant,
) -> Result<Step> {
    let Some(id) = &state.activity_id else {
        // Unknown submission outcome: search by fingerprint, oldest pages last.
        let mut after = String::new();
        let mut seen = std::collections::HashSet::new();
        loop {
            let response = query("/public/v1/query/list_activities", &json!({"organizationId":state.organization_id,"filterByType":["ACTIVITY_TYPE_EXPORT_SECRETS"],"paginationOptions":{"limit":"100","after":after}}), endpoint, stamper).await?;
            let activities = response
                .get("activities")
                .and_then(Value::as_array)
                .ok_or_else(|| malformed("invalid activity list"))?;
            if let Some(matched) = activities
                .iter()
                .find(|a| a["fingerprint"] == state.fingerprint)
            {
                // List projections may omit the result; bind the identity and
                // let the next step fetch the full activity.
                bind_activity(state, matched)?;
                state.save(state_file, false)?;
                return Ok(Step::Bound);
            }
            if activities.len() < 100 || Instant::now() >= deadline {
                return Ok(Step::NotFound);
            }
            after = activities
                .last()
                .and_then(|v| v["id"].as_str())
                .ok_or_else(|| malformed("missing pagination cursor"))?
                .to_owned();
            if !seen.insert(after.clone()) {
                return Err(malformed("activity pagination did not advance"));
            }
        }
    };
    let response = query(
        "/public/v1/query/get_activity",
        &json!({"organizationId":state.organization_id,"activityId":id}),
        endpoint,
        stamper,
    )
    .await?;
    let activity = response
        .get("activity")
        .ok_or_else(|| malformed("missing export activity"))?
        .clone();
    bind_activity(state, &activity)?;
    state.save(state_file, false)?;
    let completed = activity_terminal(
        &activity,
        "export was denied or failed; no plaintext file was written",
    )?;
    if !completed {
        return Ok(Step::Pending(activity));
    }
    let bundles = activity
        .pointer("/result/exportSecretsResult/secretPayloads")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("completed export omitted payload"))?;
    let [bundle] = bundles.as_slice() else {
        return Err(malformed("expected exactly one exported payload"));
    };
    let bundle = bundle
        .as_str()
        .ok_or_else(|| malformed("invalid export payload"))?;
    let plaintext = Zeroizing::new(
        decryptor
            .decrypt_secret(bundle, &state.organization_id.to_string())
            .context("verify and decrypt export bundle")?,
    );
    // A crash may have committed output before the state update. Reuse only
    // an identical protected file; never overwrite any existing destination.
    // `write_durable` already fsyncs the file and its directory.
    if fs::symlink_metadata(&state.output).is_ok() {
        let existing = read_private(&state.output, MAX_SECRET_BYTES + 1)?;
        if *existing != *plaintext {
            bail!(
                "existing output differs from the authenticated export; choose no replacement and inspect recovery state"
            );
        }
    } else {
        write_durable(&state.output, &plaintext, false).context("write exported secret")?;
    }
    state.completed = true;
    if let Some(mut key) = state.key_material.take() {
        key.zeroize();
    }
    state.save(state_file, false)?;
    Ok(Step::Completed(activity))
}

async fn state_lock(path: &Path) -> Result<FileLock> {
    let mut lock = path.as_os_str().to_owned();
    lock.push(".lock");
    FileLock::acquire(PathBuf::from(lock), "recovery state").await
}

fn private_file(path: &Path) -> Result<File> {
    #[cfg(not(unix))]
    bail!("protected Secrets files currently require a Unix filesystem");
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).context("open protected file")?;
    let metadata = file.metadata().context("inspect protected file")?;
    check(metadata.is_file(), "protected file must be regular")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        check(
            metadata.permissions().mode() & 0o077 == 0 && metadata.nlink() == 1,
            "protected file must be private (mode 0600) with one link",
        )?;
    }
    Ok(file)
}

fn read_private(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>> {
    let file = private_file(path)?;
    let mut encoded = Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(&mut encoded)
        .context("read protected file")?;
    check(
        encoded.len() as u64 <= limit,
        "protected file exceeds size limit",
    )?;
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::tests::quorum;
    use crate::errors::{Classification, ErrorCode, classify, error_details};
    use clap::Parser;
    use std::sync::{Arc, Mutex};
    use turnkey_enclave_encrypt::{P256Public, server::EnclaveEncryptServer};
    use wiremock::{
        Mock, MockServer, Request, ResponseTemplate,
        matchers::{method, path},
    };
    const ORG: &str = "00000000-0000-4000-8000-000000000001";
    const SECRET: &str = "00000000-0000-4000-8000-000000000002";
    const ACTIVITY: &str = "00000000-0000-4000-8000-000000000003";
    fn activity(body: &str, status: &str, result: Value) -> Value {
        let parsed: Value = serde_json::from_str(body).unwrap();
        json!({"activity":{"id":ACTIVITY,"organizationId":parsed["organizationId"],"type":parsed["type"],"fingerprint":fingerprint(body),"status":status,"intent":{"exportSecretsIntent":parsed["parameters"]},"result":result}})
    }
    fn code(error: &anyhow::Error) -> ErrorCode {
        classify(error).code
    }
    #[derive(Parser)]
    struct ParserCli {
        #[command(subcommand)]
        command: SecretCommand,
    }
    #[test]
    fn parser_rejects_secret_arguments_and_unsafe_shapes() {
        for args in [
            vec!["tk", "export", SECRET],
            vec![
                "tk",
                "export",
                "bad",
                "--output",
                "out",
                "--state-file",
                "state",
            ],
            vec!["tk", "import", "--name", "x", "--input-json", "secret"],
            vec!["tk", "list", "--limit", "0"],
            vec!["tk", "resume", "--state-file", "state", "--timeout", "0"],
        ] {
            assert!(ParserCli::try_parse_from(args).is_err());
        }
    }
    #[test]
    fn paths_and_properties_fail_before_authentication() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        fs::write(&out, b"original").unwrap();
        let error = SecretCommand::Export {
            id: Uuid::parse_str(SECRET).unwrap(),
            output: out.clone(),
            state_file: dir.path().join("state"),
            timeout: 1,
        }
        .prepare()
        .err()
        .unwrap();
        assert_eq!(code(&error), ErrorCode::InvalidInput);
        assert_eq!(fs::read(&out).unwrap(), b"original");
        let properties = dir.path().join("properties");
        fs::write(&properties, br#"{"sensitive":42}"#).unwrap();
        let error = SecretCommand::Import {
            name: "x".into(),
            input_file: out,
            static_properties_file: Some(properties),
            init_activity_id: None,
        }
        .prepare()
        .err()
        .unwrap();
        assert_eq!(code(&error), ErrorCode::InvalidInput);
    }
    #[tokio::test]
    async fn metadata_list_paginates_and_strips_unknown_payload_fields() {
        let server = MockServer::start().await;
        Mock::given(path("/public/v1/query/list_secrets")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"secrets":[{"secretId":SECRET,"name":"token","secretPayload":"must-not-output"}]}))).expect(1).mount(&server).await;
        let (_, q) = quorum();
        let out = PreparedSecret::List {
            limit: 1,
            cursor: Some(Uuid::parse_str(ACTIVITY).unwrap()),
        }
        .run_with_key(ORG, &server.uri(), &TurnkeyP256ApiKey::generate(), &q)
        .await
        .unwrap();
        assert_eq!(
            out.data(),
            &json!({"items":[{"secretId":SECRET,"name":"token","staticProperties":[],"createdAtUnixMs":null}],"nextCursor":SECRET})
        );
        let body: Value =
            serde_json::from_slice(&server.received_requests().await.unwrap()[0].body).unwrap();
        assert_eq!(
            body["paginationOptions"],
            json!({"limit":"1","after":ACTIVITY})
        );
    }
    #[tokio::test]
    async fn import_encrypts_bytes_and_submits_only_ciphertext() {
        let server = MockServer::start().await;
        let (signing, q) = quorum();
        let enclave =
            EnclaveEncryptServer::from_enclave_auth_key(signing, ORG.into(), Some("user".into()));
        let bundle = serde_json::to_string(&enclave.publish_target().unwrap()).unwrap();
        let mut receiver = enclave.into_recv();
        Mock::given(path("/public/v1/submit/init_import_secrets"))
            .respond_with(move |r: &Request| {
                ResponseTemplate::new(200).set_body_json(activity(
                    std::str::from_utf8(&r.body).unwrap(),
                    "ACTIVITY_STATUS_COMPLETED",
                    json!({"initImportSecretsResult":{"enclaveTargetMessages":[bundle]}}),
                ))
            })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/public/v1/submit/import_secrets"))
            .respond_with(|r: &Request| {
                ResponseTemplate::new(200).set_body_json(activity(
                    std::str::from_utf8(&r.body).unwrap(),
                    "ACTIVITY_STATUS_COMPLETED",
                    json!({"importSecretsResult":{"secretIds":[SECRET]}}),
                ))
            })
            .expect(1)
            .mount(&server)
            .await;
        let plaintext = b"synthetic-token-\x00\xff";
        let out = PreparedSecret::Import {
            name: "demo".into(),
            plaintext: Zeroizing::new(plaintext.to_vec()),
            properties: std::collections::BTreeMap::from([("purpose".into(), "demo".into())]),
            init_activity_id: None,
        }
        .run_with_key(ORG, &server.uri(), &TurnkeyP256ApiKey::generate(), &q)
        .await
        .unwrap();
        assert_eq!(out.data()["secretIds"], json!([SECRET]));
        let requests = server.received_requests().await.unwrap();
        let body: Value = serde_json::from_slice(&requests[1].body).unwrap();
        let payload = serde_json::from_str(
            body["parameters"]["secrets"][0]["secretPayload"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(receiver.decrypt(&payload).unwrap(), plaintext);
        assert_eq!(
            body["parameters"]["secrets"][0]["staticProperties"],
            json!([{"key":"purpose","value":"demo"}])
        );
        assert!(!String::from_utf8_lossy(&requests[1].body).contains("synthetic-token"));
        assert!(
            !serde_json::to_string(&out)
                .unwrap()
                .contains("synthetic-token")
        );
    }
    #[tokio::test]
    async fn export_persists_exact_proposal_before_submit_and_scrubs_key_after_durable_output() {
        let server = MockServer::start().await;
        let (signing, q) = quorum();
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("secret");
        let state_path = dir.path().join("state");
        let check_path = state_path.clone();
        let response = Arc::new(Mutex::new(Value::Null));
        let stored = response.clone();
        Mock::given(method("POST"))
            .and(path("/public/v1/submit/export_secrets"))
            .respond_with(move |r: &Request| {
                let body = std::str::from_utf8(&r.body).unwrap();
                let state = ExportState::read(&check_path).unwrap();
                assert_eq!(state.proposal, body);
                let parsed: Value = serde_json::from_str(body).unwrap();
                let target: P256Public = hex::decode(
                    parsed["parameters"]["secrets"][0]["targetPublicKey"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap()
                .try_into()
                .unwrap();
                let enclave =
                    EnclaveEncryptServer::from_enclave_auth_key(signing.clone(), ORG.into(), None);
                let bundle = serde_json::to_string(
                    &enclave
                        .encrypt(&target, b"synthetic secret\x00\xff")
                        .unwrap(),
                )
                .unwrap();
                let value = activity(
                    body,
                    "ACTIVITY_STATUS_COMPLETED",
                    json!({"exportSecretsResult":{"secretPayloads":[bundle]}}),
                );
                *stored.lock().unwrap() = value.clone();
                ResponseTemplate::new(200).set_body_json(value)
            })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/public/v1/query/get_activity"))
            .respond_with(move |_: &Request| {
                ResponseTemplate::new(200).set_body_json(response.lock().unwrap().clone())
            })
            .mount(&server)
            .await;
        let key = TurnkeyP256ApiKey::generate();
        PreparedSecret::Export {
            id: Uuid::parse_str(SECRET).unwrap(),
            output: output.clone(),
            state_file: state_path.clone(),
            timeout: 1,
        }
        .run_with_key(ORG, &server.uri(), &key, &q)
        .await
        .unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"synthetic secret\x00\xff");
        let state = ExportState::read(&state_path).unwrap();
        assert!(state.completed);
        assert!(state.key_material.is_none());
        drop(state);
        let out = PreparedSecret::Resume {
            state_file: state_path,
            timeout: 1,
        }
        .run_with_key(ORG, &server.uri(), &key, &q)
        .await
        .unwrap();
        assert!(
            !serde_json::to_string(&out)
                .unwrap()
                .contains("synthetic secret")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    fn recovery_state(
        endpoint: &str,
        key: &TurnkeyP256ApiKey,
        q: &QuorumPublicKey,
        output: PathBuf,
    ) -> ExportState {
        let ikm = [7u8; 32];
        let target = SecretRecipient::from_ikm(&ikm, q)
            .unwrap()
            .target_public_key()
            .unwrap();
        let proposal = serde_json::to_string(&envelope_at(
            "ACTIVITY_TYPE_EXPORT_SECRETS",
            ORG,
            "1",
            &json!({"secrets":[{"secretId":SECRET,"targetPublicKey":target,"encryptionSuite":SUITE}]}),
        ))
        .unwrap();
        ExportState {
            version: 1,
            organization_id: Uuid::parse_str(ORG).unwrap(),
            api_base_url: endpoint.into(),
            identity_public_key: hex::encode(key.compressed_public_key()),
            secret_id: Uuid::parse_str(SECRET).unwrap(),
            target_public_key: target,
            fingerprint: fingerprint(&proposal),
            proposal,
            output,
            key_material: Some(hex::encode(ikm)),
            activity_id: None,
            completed: false,
        }
    }
    #[tokio::test]
    async fn unknown_submission_resume_discovers_fingerprint_and_denial_never_replays() {
        let server = MockServer::start().await;
        let (_, q) = quorum();
        let key = TurnkeyP256ApiKey::generate();
        let dir = tempfile::tempdir().unwrap();
        let path_state = dir.path().join("state");
        let state = recovery_state(&server.uri(), &key, &q, dir.path().join("out"));
        let value = activity(&state.proposal, "ACTIVITY_STATUS_REJECTED", Value::Null);
        state.save(&path_state, true).unwrap();
        Mock::given(path("/public/v1/query/list_activities"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"activities":[value["activity"]]})),
            )
            .expect(1)
            .mount(&server)
            .await;
        // The discovered identity is fetched in full before it is interpreted.
        Mock::given(path("/public/v1/query/get_activity"))
            .respond_with(ResponseTemplate::new(200).set_body_json(value.clone()))
            .expect(1)
            .mount(&server)
            .await;
        drop(state);
        let error = PreparedSecret::Resume {
            state_file: path_state.clone(),
            timeout: 1,
        }
        .run_with_key(ORG, &server.uri(), &key, &q)
        .await
        .unwrap_err();
        assert_eq!(code(&error), ErrorCode::ApiError);
        let details = error_details(&error).unwrap();
        assert_eq!(details["activity"]["id"], ACTIVITY);
        assert_eq!(details["stateFile"], path_state.to_str().unwrap());
        assert!(!format!("{error:#}").contains(&hex::encode([7u8; 32])));
        assert!(!dir.path().join("out").exists());
        let bound = ExportState::read(&path_state).unwrap();
        assert!(bound.key_material.is_some());
        assert_eq!(bound.activity_id.as_deref(), Some(ACTIVITY));
        server.verify().await;
    }
    #[tokio::test]
    async fn pending_times_out_with_recovery_and_wrong_identity_makes_no_request() {
        let server = MockServer::start().await;
        let (_, q) = quorum();
        let key = TurnkeyP256ApiKey::generate();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state");
        let mut state = recovery_state(&server.uri(), &key, &q, dir.path().join("out"));
        state.activity_id = Some(ACTIVITY.into());
        let value = activity(
            &state.proposal,
            "ACTIVITY_STATUS_CONSENSUS_NEEDED",
            Value::Null,
        );
        state.save(&state_path, true).unwrap();
        Mock::given(path("/public/v1/query/get_activity"))
            .respond_with(ResponseTemplate::new(200).set_body_json(value))
            .mount(&server)
            .await;
        drop(state);
        let error = PreparedSecret::Resume {
            state_file: state_path.clone(),
            timeout: 1,
        }
        .run_with_key(ORG, &server.uri(), &key, &q)
        .await
        .unwrap_err();
        assert_eq!(
            classify(&error),
            Classification::new(ErrorCode::WaitTimeout, None)
        );
        assert_eq!(error_details(&error).unwrap()["activity"]["id"], ACTIVITY);
        server.reset().await;
        let before = server.received_requests().await.unwrap().len();
        let error = PreparedSecret::Resume {
            state_file: state_path,
            timeout: 1,
        }
        .run_with_key(ORG, &server.uri(), &TurnkeyP256ApiKey::generate(), &q)
        .await
        .unwrap_err();
        assert_eq!(code(&error), ErrorCode::InvalidInput);
        assert_eq!(server.received_requests().await.unwrap().len(), before);
    }
    #[tokio::test]
    async fn recovery_rejects_wrong_activity_or_corrupt_bundle_without_output() {
        for corrupt_bundle in [false, true] {
            let server = MockServer::start().await;
            let (_, q) = quorum();
            let key = TurnkeyP256ApiKey::generate();
            let dir = tempfile::tempdir().unwrap();
            let state_path = dir.path().join("state");
            let mut state = recovery_state(&server.uri(), &key, &q, dir.path().join("out"));
            state.activity_id = Some(ACTIVITY.into());
            let mut value = activity(
                &state.proposal,
                "ACTIVITY_STATUS_COMPLETED",
                json!({"exportSecretsResult":{"secretPayloads":["malformed"]}}),
            );
            if !corrupt_bundle {
                value["activity"]["fingerprint"] = json!("sha256:wrong");
            }
            state.save(&state_path, true).unwrap();
            Mock::given(path("/public/v1/query/get_activity"))
                .respond_with(ResponseTemplate::new(200).set_body_json(value))
                .mount(&server)
                .await;
            drop(state);
            assert!(
                PreparedSecret::Resume {
                    state_file: state_path.clone(),
                    timeout: 1
                }
                .run_with_key(ORG, &server.uri(), &key, &q)
                .await
                .is_err()
            );
            assert!(!dir.path().join("out").exists());
            assert!(
                ExportState::read(&state_path)
                    .unwrap()
                    .key_material
                    .is_some()
            );
        }
    }

    #[tokio::test]
    async fn malformed_submission_is_unknown_and_resume_does_not_submit_again() {
        let server = MockServer::start().await;
        let (_, q) = quorum();
        let key = TurnkeyP256ApiKey::generate();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state");
        Mock::given(path("/public/v1/submit/export_secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&server)
            .await;
        let error = PreparedSecret::Export {
            id: Uuid::parse_str(SECRET).unwrap(),
            output: dir.path().join("out"),
            state_file: state_path.clone(),
            timeout: 1,
        }
        .run_with_key(ORG, &server.uri(), &key, &q)
        .await
        .unwrap_err();
        assert_eq!(code(&error), ErrorCode::SubmissionUnknown);
        assert_eq!(
            error_details(&error).unwrap()["stateFile"],
            state_path.to_str().unwrap()
        );
        let state = ExportState::read(&state_path).unwrap();
        Mock::given(path("/public/v1/query/list_activities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"activities":[]})))
            .mount(&server)
            .await;
        drop(state);
        let error = PreparedSecret::Resume {
            state_file: state_path.clone(),
            timeout: 1,
        }
        .run_with_key(ORG, &server.uri(), &key, &q)
        .await
        .unwrap_err();
        // Still never observed, so the outcome stays unknown rather than slow.
        assert_eq!(code(&error), ErrorCode::SubmissionUnknown);
        assert_eq!(
            error_details(&error).unwrap()["stateFile"],
            state_path.to_str().unwrap()
        );
        server.verify().await;
    }
    #[tokio::test]
    async fn rejected_export_submission_removes_state_and_says_start_over() {
        let server = MockServer::start().await;
        let (_, q) = quorum();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state");
        Mock::given(path("/public/v1/submit/export_secrets"))
            .respond_with(
                ResponseTemplate::new(400).set_body_json(json!({"message":"bad request"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let error = PreparedSecret::Export {
            id: Uuid::parse_str(SECRET).unwrap(),
            output: dir.path().join("out"),
            state_file: state_path.clone(),
            timeout: 1,
        }
        .run_with_key(ORG, &server.uri(), &TurnkeyP256ApiKey::generate(), &q)
        .await
        .unwrap_err();
        assert_eq!(
            classify(&error),
            Classification::new(ErrorCode::ApiError, Some(400))
        );
        assert_eq!(error_details(&error).unwrap()["phase"], "submit");
        assert!(format!("{error:#}").contains("start a new export"));
        assert!(!state_path.exists());
        assert!(!dir.path().join("out").exists());
    }
    #[tokio::test]
    async fn pending_initialization_reports_next_step_without_encrypting() {
        let server = MockServer::start().await;
        let (_, q) = quorum();
        Mock::given(path("/public/v1/submit/init_import_secrets"))
            .respond_with(|r: &Request| {
                ResponseTemplate::new(200).set_body_json(activity(
                    std::str::from_utf8(&r.body).unwrap(),
                    "ACTIVITY_STATUS_CONSENSUS_NEEDED",
                    Value::Null,
                ))
            })
            .expect(1)
            .mount(&server)
            .await;
        let out = PreparedSecret::Import {
            name: "demo".into(),
            plaintext: Zeroizing::new(b"synthetic".to_vec()),
            properties: Default::default(),
            init_activity_id: None,
        }
        .run_with_key(ORG, &server.uri(), &TurnkeyP256ApiKey::generate(), &q)
        .await
        .unwrap();
        let record = serde_json::to_value(&out).unwrap();
        assert_eq!(record["status"], "pending");
        assert_eq!(record["data"]["phase"], "init-import");
        assert_eq!(record["data"]["activity"]["id"], ACTIVITY);
        assert!(!record.to_string().contains("synthetic"));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
    #[tokio::test]
    async fn crash_after_output_publication_reconciles_only_identical_private_bytes() {
        for identical in [true, false] {
            let server = MockServer::start().await;
            let (signing, q) = quorum();
            let key = TurnkeyP256ApiKey::generate();
            let dir = tempfile::tempdir().unwrap();
            let state_path = dir.path().join("state");
            let output = dir.path().join("out");
            let mut state = recovery_state(&server.uri(), &key, &q, output.clone());
            state.activity_id = Some(ACTIVITY.into());
            let target: P256Public = hex::decode(&state.target_public_key)
                .unwrap()
                .try_into()
                .unwrap();
            let enclave = EnclaveEncryptServer::from_enclave_auth_key(signing, ORG.into(), None);
            let bundle =
                serde_json::to_string(&enclave.encrypt(&target, b"synthetic token").unwrap())
                    .unwrap();
            let response = activity(
                &state.proposal,
                "ACTIVITY_STATUS_COMPLETED",
                json!({"exportSecretsResult":{"secretPayloads":[bundle]}}),
            );
            state.save(&state_path, true).unwrap();
            let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
            file.write_all(if identical {
                b"synthetic token"
            } else {
                b"other bytes"
            })
            .unwrap();
            file.persist_noclobber(&output).unwrap();
            Mock::given(path("/public/v1/query/get_activity"))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .mount(&server)
                .await;
            drop(state);
            let result = PreparedSecret::Resume {
                state_file: state_path.clone(),
                timeout: 1,
            }
            .run_with_key(ORG, &server.uri(), &key, &q)
            .await;
            assert_eq!(result.is_ok(), identical);
            assert_eq!(ExportState::read(&state_path).unwrap().completed, identical);
            assert_eq!(
                fs::read(&output).unwrap(),
                if identical {
                    b"synthetic token".to_vec()
                } else {
                    b"other bytes".to_vec()
                }
            );
        }
    }
    #[tokio::test]
    async fn initialization_resume_denial_or_wrong_id_never_imports() {
        for wrong_id in [true, false] {
            let server = MockServer::start().await;
            let (_, q) = quorum();
            let response = json!({"activity":{"id":if wrong_id {SECRET} else {ACTIVITY},"organizationId":ORG,"type":"ACTIVITY_TYPE_INIT_IMPORT_SECRETS","status":"ACTIVITY_STATUS_REJECTED","intent":{"initImportSecretsIntent":{"encryptionSuite":SUITE,"numSecrets":1}}}});
            Mock::given(path("/public/v1/query/get_activity"))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .expect(1)
                .mount(&server)
                .await;
            let error = PreparedSecret::Import {
                name: "demo".into(),
                plaintext: Zeroizing::new(b"synthetic".to_vec()),
                properties: Default::default(),
                init_activity_id: Some(Uuid::parse_str(ACTIVITY).unwrap()),
            }
            .run_with_key(ORG, &server.uri(), &TurnkeyP256ApiKey::generate(), &q)
            .await
            .unwrap_err();
            let failure = error.downcast_ref::<ActivityError>().unwrap();
            if wrong_id {
                assert_eq!(failure.kind(), ActivityErrorKind::MalformedResponse);
            } else {
                assert_eq!(failure.kind(), ActivityErrorKind::NotCompleted);
                assert_eq!(error_details(&error).unwrap()["phase"], "init-import");
            }
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn unknown_recovery_walks_older_activity_pages_using_after() {
        let server = MockServer::start().await;
        let (_, q) = quorum();
        let key = TurnkeyP256ApiKey::generate();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state");
        let state = recovery_state(&server.uri(), &key, &q, dir.path().join("out"));
        let matched = activity(&state.proposal, "ACTIVITY_STATUS_REJECTED", Value::Null);
        state.save(&state_path, true).unwrap();
        Mock::given(path("/public/v1/query/get_activity"))
            .respond_with(ResponseTemplate::new(200).set_body_json(matched.clone()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/public/v1/query/list_activities")).respond_with(move |r:&Request| {
            let body:Value=serde_json::from_slice(&r.body).unwrap();let cursor=body["paginationOptions"]["after"].as_str().unwrap();
            if cursor.is_empty() { ResponseTemplate::new(200).set_body_json(json!({"activities":(0..100).map(|i|json!({"id":format!("newer-{i}"),"fingerprint":"other"})).collect::<Vec<_>>()})) }
            else { assert_eq!(cursor,"newer-99"); ResponseTemplate::new(200).set_body_json(json!({"activities":[matched["activity"]]})) }
        }).expect(2).mount(&server).await;
        drop(state);
        let error = PreparedSecret::Resume {
            state_file: state_path,
            timeout: 1,
        }
        .run_with_key(ORG, &server.uri(), &key, &q)
        .await
        .unwrap_err();
        assert_eq!(code(&error), ErrorCode::ApiError);
        assert_eq!(error_details(&error).unwrap()["activity"]["id"], ACTIVITY);
        server.verify().await;
    }
    #[test]
    fn recovery_schema_rejects_proposal_or_completion_tampering() {
        let (_, q) = quorum();
        let key = TurnkeyP256ApiKey::generate();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state");
        let mut state = recovery_state("https://api.turnkey.com", &key, &q, dir.path().join("out"));
        state.fingerprint = "wrong".into();
        state.save(&state_path, true).unwrap();
        assert!(ExportState::read(&state_path).is_err());
        state.fingerprint = fingerprint(&state.proposal);
        state.completed = true;
        state.save(&state_path, false).unwrap();
        assert!(ExportState::read(&state_path).is_err());
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn recovery_refuses_symlinks_hardlinks_world_readable_and_concurrent_access() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"{}").unwrap();
        let link = dir.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(read_private(&link, 100).is_err());
        assert!(new_path(link).is_err());
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private(&target, 100).is_err());
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&target, dir.path().join("hard")).unwrap();
        assert!(read_private(&target, 100).is_err());
        let _lock = state_lock(&target).await.unwrap();
        assert!(state_lock(&target).await.is_err());
    }
}
