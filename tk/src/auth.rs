use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use reqwest::{ClientBuilder, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeMap,
    io::ErrorKind,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
};
use tracing::debug;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::TurnkeyClient;
use turnkey_client::generated::GetWhoamiRequest;
use uuid::Uuid;

use crate::errors::{InvalidInput, OrganizationMismatch};
use crate::gpg::registry::{GpgKeyEntry, GpgKeyTable, SelectError, SigningKeyName, StoredGpgKey};
use crate::operations::OperationOutput;

const DEFAULT_URL: &str = "https://api.turnkey.com";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Default, Args)]
pub struct AuthOptions {
    /// Identity registry path.
    #[arg(long, global = true, env = "TK_CONFIG")]
    config: Option<PathBuf>,
    /// Named profile to use from the identity registry. An explicit profile
    /// always wins over ambient TURNKEY_* environment credentials.
    #[arg(long, global = true, env = "TK_PROFILE")]
    profile: Option<String>,
    /// Override the organization the command operates on.
    #[arg(long, global = true)]
    organization_id: Option<Uuid>,
    /// Override the API base URL.
    #[arg(long, global = true)]
    api_base_url: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Save and select an existing API credential after verifying it remotely.
    Login(LoginArgs),
    /// Inspect local credential readiness without contacting the server.
    Status,
    /// Verify the selected identity with Turnkey.
    Whoami,
    /// Clear the saved profile selection; keep credentials and remote access intact.
    Logout,
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Name for the new profile.
    name: String,
    /// Existing P256 credential JSON file (public_key, private_key, curve).
    #[arg(long)]
    api_key_file: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// List saved profiles and the active selection.
    List,
    /// Show one saved profile.
    Show { name: String },
    /// Select a saved profile after checking its credential file.
    Use { name: String },
    /// Remove a profile entry; credential files are kept.
    Delete { name: String },
}

#[derive(Serialize, Deserialize)]
pub struct StoredApiKey {
    pub public_key: String,
    pub private_key: String,
    pub curve: KeyCurve,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KeyCurve {
    P256,
}

#[derive(Deserialize)]
struct RegistryVersion {
    version: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    version: u32,
    active_profile: Option<String>,
    #[serde(default)]
    profiles: BTreeMap<String, Profile>,
    /// OpenPGP keys by fingerprint, shared by every profile because a key
    /// belongs to an organization.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    gpg_keys: BTreeMap<String, StoredGpgKey>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            version: 1,
            active_profile: None,
            profiles: BTreeMap::new(),
            gpg_keys: BTreeMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    organization_id: Uuid,
    api_base_url: String,
    api_key_file: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_signing_key_id: Option<String>,
}

pub struct ResolvedAuth {
    /// `organization_id` rendered for the wire types, which take strings.
    pub org_id: String,
    pub organization_id: Uuid,
    pub api_base_url: String,
    pub stamper: TurnkeyP256ApiKey,
    source: &'static str,
    profile: Option<String>,
}

impl ResolvedAuth {
    fn new(
        organization_id: Uuid,
        api_base_url: String,
        stamper: TurnkeyP256ApiKey,
        source: &'static str,
        profile: Option<String>,
    ) -> Self {
        Self {
            org_id: organization_id.to_string(),
            organization_id,
            api_base_url,
            stamper,
            source,
            profile,
        }
    }
}

#[cfg(test)]
impl ResolvedAuth {
    pub fn for_tests(org_id: &str, api_base_url: &str, stamper: TurnkeyP256ApiKey) -> Self {
        let organization_id = Uuid::parse_str(org_id).expect("test organization ids are UUIDs");
        Self::new(organization_id, api_base_url.into(), stamper, "test", None)
    }
}

pub fn transport(builder: ClientBuilder) -> ClientBuilder {
    builder.redirect(Policy::none()).timeout(REQUEST_TIMEOUT)
}

pub fn build_turnkey_client(
    stamper: TurnkeyP256ApiKey,
    api_base_url: &str,
) -> Result<TurnkeyClient<TurnkeyP256ApiKey>> {
    TurnkeyClient::builder()
        .api_key(stamper)
        .base_url(api_base_url)
        .with_reqwest_builder(transport)
        .build()
        .context("failed to build Turnkey client")
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn home() -> Result<PathBuf> {
    env("HOME")
        .map(PathBuf::from)
        .context("HOME is required when no explicit configuration path is supplied")
}

fn registry_path(options: &AuthOptions) -> Result<PathBuf> {
    match &options.config {
        Some(path) => Ok(path.clone()),
        None => Ok(home()?.join(".config/turnkey/tk.config.toml")),
    }
}

/// Returns the directory for tk-managed state.
pub(crate) fn state_dir() -> Result<PathBuf> {
    Ok(home()?.join(".config/turnkey/tk"))
}

/// Removes files older than `max_age`, ignoring a missing directory.
pub(crate) async fn sweep_stale(dir: &Path, max_age: Duration) -> std::io::Result<usize> {
    let cutoff = SystemTime::now()
        .checked_sub(max_age)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let mut removed = 0;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let mut entries = match fs::read_dir(&current).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        while let Some(entry) = entries.next_entry().await? {
            let metadata = entry.metadata().await?;
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() && metadata.modified()? < cutoff {
                fs::remove_file(entry.path()).await?;
                removed += 1;
            }
        }
    }
    Ok(removed)
}

/// Best-effort cleanup of stale pending-export recovery keys.
pub(crate) async fn sweep_state() {
    const PENDING_EXPORT_LIFETIME: Duration = Duration::from_secs(8 * 60 * 60);
    let result = match state_dir() {
        Ok(dir) => sweep_stale(&dir.join("secrets/pending"), PENDING_EXPORT_LIFETIME).await,
        Err(error) => {
            debug!(%error, "skipping state sweep");
            return;
        }
    };
    match result {
        Ok(0) => {}
        Ok(removed) => debug!(removed, "swept stale pending export state"),
        Err(error) => debug!(%error, "state sweep failed"),
    }
}

async fn load(path: &Path) -> Result<Registry> {
    let text = match fs::read_to_string(path).await {
        Ok(text) => text,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Registry::default()),
        Err(e) => return Err(e).with_context(|| format!("read registry {}", path.display())),
    };
    let invalid = || InvalidInput(format!("invalid identity registry {}", path.display()));
    let RegistryVersion { version } = toml::from_str(&text).map_err(|_| invalid())?;
    if version != 1 {
        bail!(
            "unsupported registry version {version} in {}",
            path.display()
        );
    }
    let registry: Registry = toml::from_str(&text).map_err(|_| invalid())?;
    if let Some((name, profile)) = registry
        .profiles
        .iter()
        .find(|(_, profile)| profile.api_key_file.is_relative())
    {
        return Err(InvalidInput(format!(
            "profile {name} in {} has relative api_key_file {}; use an absolute path",
            path.display(),
            profile.api_key_file.display()
        ))
        .into());
    }
    Ok(registry)
}

pub(crate) struct FileLock {
    _file: fs::File,
}

#[derive(Debug, thiserror::Error)]
#[error("{resource} is locked by another tk process ({}); retry after it completes", lock.display())]
pub(crate) struct LockHeld {
    resource: String,
    lock: PathBuf,
}

impl FileLock {
    pub(crate) async fn acquire(lock: PathBuf, resource: &str) -> Result<Self> {
        if let Some(parent) = lock.parent() {
            fs::create_dir_all(parent).await?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options
            .open(&lock)
            .await
            .with_context(|| format!("open lock {}", lock.display()))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: flock only reads the descriptor, which stays open for the
            // lifetime of `file`.
            let status = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if status != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == ErrorKind::WouldBlock {
                    return Err(LockHeld {
                        resource: resource.into(),
                        lock,
                    }
                    .into());
                }
                return Err(error).with_context(|| format!("lock {}", lock.display()));
            }
        }
        Ok(Self { _file: file })
    }
}

async fn registry_lock(path: &Path) -> Result<FileLock> {
    FileLock::acquire(path.with_extension("lock"), "identity registry").await
}

async fn save(path: &Path, registry: &Registry) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    let temporary = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let content = toml::to_string_pretty(registry)?;
    secure_create(&temporary, content.as_bytes())
        .await
        .with_context(|| format!("create {}", temporary.display()))?;
    if let Err(error) = fs::rename(&temporary, path).await {
        let _ = fs::remove_file(&temporary).await;
        return Err(error).context("replace identity registry");
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum SecureCreateError {
    #[error("refusing to overwrite an existing file")]
    Exists,
    #[error(transparent)]
    Io(std::io::Error),
}

pub async fn secure_create(path: &Path, contents: &[u8]) -> Result<(), SecureCreateError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).await.map_err(|error| {
        if error.kind() == ErrorKind::AlreadyExists {
            SecureCreateError::Exists
        } else {
            SecureCreateError::Io(error)
        }
    })?;
    let written = match file.write_all(contents).await {
        Ok(()) => file.sync_all().await,
        Err(error) => Err(error),
    };
    if let Err(error) = written {
        let _ = fs::remove_file(path).await;
        return Err(SecureCreateError::Io(error));
    }
    Ok(())
}

fn parse_key(private: &str, public: &str) -> Result<TurnkeyP256ApiKey> {
    let bytes = hex::decode(private)
        .map_err(|_| InvalidInput("private credential must be hexadecimal".into()))?;
    if bytes.len() != 32 {
        return Err(
            InvalidInput("P256 private credentials must contain exactly 32 bytes".into()).into(),
        );
    }
    TurnkeyP256ApiKey::from_strings(private, Some(public))
        .map_err(|_| InvalidInput("invalid P256 credential pair".into()).into())
}

async fn read_key(path: &Path) -> Result<TurnkeyP256ApiKey> {
    let text = fs::read_to_string(path)
        .await
        .with_context(|| format!("read credential {}", path.display()))?;
    let key: StoredApiKey = serde_json::from_str(&text)
        .map_err(|_| InvalidInput(format!("invalid credential JSON in {}", path.display())))?;
    parse_key(&key.private_key, &key.public_key)
}

fn endpoint(options: &AuthOptions, fallback: String) -> Result<String> {
    let endpoint = options
        .api_base_url
        .clone()
        .or_else(|| env("TURNKEY_API_BASE_URL"))
        .unwrap_or(fallback);
    parse_endpoint(endpoint)
}

fn parse_endpoint(endpoint: String) -> Result<String> {
    let url =
        reqwest::Url::parse(&endpoint).map_err(|_| InvalidInput("invalid API base URL".into()))?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(InvalidInput(
            "API base URL must be an HTTP(S) URL without credentials, query or fragment".into(),
        )
        .into());
    }
    Ok(endpoint)
}

const ENV_BUNDLE: [&str; 3] = [
    "TURNKEY_ORGANIZATION_ID",
    "TURNKEY_API_PUBLIC_KEY",
    "TURNKEY_API_PRIVATE_KEY",
];

pub async fn resolve(options: &AuthOptions) -> Result<ResolvedAuth> {
    if let Some(auth) = resolve_environment(options)? {
        return Ok(auth);
    }
    let path = registry_path(options)?;
    let registry = load(&path).await?;
    let name = options
        .profile
        .clone()
        .or(registry.active_profile.clone())
        .ok_or_else(|| InvalidInput("no selected identity; use --profile or tk login".into()))?;
    let profile = registry.profiles.get(&name).ok_or_else(|| {
        InvalidInput(format!(
            "profile {name} does not exist in {}",
            path.display()
        ))
    })?;
    resolve_profile(options, name, profile).await
}

/// Credentials for `organization_id`, the owner of a key about to be used.
/// An explicit identity (the environment bundle, `--profile`, `TK_PROFILE`,
/// or `--organization-id`) must belong to that organization. Without one,
/// the registry's profiles for the organization are searched: the only one,
/// or the active profile when several qualify.
pub async fn resolve_for_organization(
    options: &AuthOptions,
    organization_id: Uuid,
) -> Result<ResolvedAuth> {
    let check = |auth: ResolvedAuth| {
        if auth.organization_id == organization_id {
            Ok(auth)
        } else {
            Err(OrganizationMismatch {
                expected: organization_id,
                actual: auth.organization_id,
                identity: auth.source,
            }
            .into())
        }
    };
    if let Some(actual) = options.organization_id
        && actual != organization_id
    {
        return Err(OrganizationMismatch {
            expected: organization_id,
            actual,
            identity: "--organization-id",
        }
        .into());
    }
    // An explicit profile or the environment bundle resolves as any other
    // command does and is then checked against the organization.
    if options.profile.is_some() {
        return check(resolve(options).await?);
    }
    if let Some(auth) = resolve_environment(options)? {
        return check(auth);
    }
    let path = registry_path(options)?;
    let registry = load(&path).await?;
    let candidates: Vec<(&String, &Profile)> = registry
        .profiles
        .iter()
        .filter(|(_, profile)| profile.organization_id == organization_id)
        .collect();
    let (name, profile) = match candidates.as_slice() {
        [] => {
            return Err(InvalidInput(format!(
                "no profile holds a credential for organization {organization_id}; run tk login <name> --organization-id {organization_id} --api-key-file <path>"
            ))
            .into());
        }
        [(name, profile)] => (*name, *profile),
        several => {
            let active = registry.active_profile.as_ref();
            match several.iter().find(|(name, _)| Some(*name) == active) {
                Some((name, profile)) => (*name, *profile),
                None => {
                    let names: Vec<&str> = several.iter().map(|(name, _)| name.as_str()).collect();
                    return Err(InvalidInput(format!(
                        "profiles {} all hold a credential for organization {organization_id}; select one with --profile, TK_PROFILE, or tk profile use",
                        names.join(", ")
                    ))
                    .into());
                }
            }
        }
    };
    resolve_profile(options, name.clone(), profile).await
}

/// The `TURNKEY_*` bundle, which an explicit `--profile` disables. `None`
/// when no bundle variable is set.
fn resolve_environment(options: &AuthOptions) -> Result<Option<ResolvedAuth>> {
    if options.profile.is_some() {
        return Ok(None);
    }
    let bundle = ENV_BUNDLE.map(std::env::var_os);
    if bundle.iter().all(Option::is_none) {
        return Ok(None);
    }
    let [org, public, private] = bundle;
    let (Some(org), Some(public), Some(private)) = (org, public, private) else {
        return Err(InvalidInput(
            "partial credential environment: organization ID, public key, and private key are all required".into(),
        )
        .into());
    };
    let [org, public, private] = [org, public, private].map(|value| {
        value
            .into_string()
            .map_err(|_| InvalidInput("credential environment value is not valid Unicode".into()))
    });
    let (org, public, private) = (org?, public?, private?);
    if org.is_empty() || public.is_empty() || private.is_empty() {
        return Err(InvalidInput("credential environment fields must not be empty".into()).into());
    }
    let org = match options.organization_id {
        Some(org) => org,
        None => Uuid::parse_str(&org)
            .map_err(|_| InvalidInput("invalid environment organization ID".into()))?,
    };
    Ok(Some(ResolvedAuth::new(
        org,
        endpoint(options, DEFAULT_URL.into())?,
        parse_key(&private, &public)?,
        "environment",
        None,
    )))
}

async fn resolve_profile(
    options: &AuthOptions,
    name: String,
    profile: &Profile,
) -> Result<ResolvedAuth> {
    Ok(ResolvedAuth::new(
        options.organization_id.unwrap_or(profile.organization_id),
        endpoint(options, profile.api_base_url.clone())?,
        read_key(&profile.api_key_file).await?,
        "profile",
        Some(name),
    ))
}

fn profile_missing(name: &str) -> InvalidInput {
    InvalidInput(format!("profile {name} does not exist"))
}

/// Reading the table needs no credential.
pub async fn load_gpg_keys(options: &AuthOptions) -> Result<GpgKeyTable> {
    let path = registry_path(options)?;
    let registry = load(&path).await?;
    Ok(GpgKeyTable::from_stored(registry.gpg_keys, &path)?)
}

pub async fn register_gpg_key(options: &AuthOptions, entry: GpgKeyEntry) -> Result<()> {
    let path = registry_path(options)?;
    let _lock = registry_lock(&path).await?;
    let mut registry = load(&path).await?;
    let mut table = GpgKeyTable::from_stored(registry.gpg_keys, &path)?;
    table.insert(entry);
    registry.gpg_keys = table.into_stored();
    save(&path, &registry).await
}

pub async fn remove_gpg_key(
    options: &AuthOptions,
    name: &SigningKeyName,
) -> Result<Result<GpgKeyEntry, SelectError>> {
    let path = registry_path(options)?;
    let _lock = registry_lock(&path).await?;
    let mut registry = load(&path).await?;
    let mut table = GpgKeyTable::from_stored(registry.gpg_keys, &path)?;
    let removed = match table.remove(name) {
        Ok(entry) => entry,
        Err(error) => return Ok(Err(error)),
    };
    registry.gpg_keys = table.into_stored();
    save(&path, &registry).await?;
    Ok(Ok(removed))
}

pub async fn run_auth(command: AuthCommand, options: &AuthOptions) -> Result<OperationOutput> {
    match command {
        AuthCommand::Status => {
            let auth = resolve(options).await?;
            Ok(OperationOutput::result(
                "auth.status",
                json!({"ready": true, "profile": auth.profile, "organizationId": auth.org_id, "apiBaseUrl": auth.api_base_url, "publicKey": hex::encode(auth.stamper.compressed_public_key()), "credentialSource": auth.source}),
            ))
        }
        AuthCommand::Whoami => {
            let auth = resolve(options).await?;
            let identity = build_turnkey_client(auth.stamper, &auth.api_base_url)?
                .get_whoami(GetWhoamiRequest {
                    organization_id: auth.org_id,
                })
                .await
                .map_err(anyhow::Error::new)
                .context("Turnkey API request failed")?;
            Ok(OperationOutput::result(
                "auth.whoami",
                serde_json::to_value(identity)?,
            ))
        }
        AuthCommand::Logout => {
            let path = registry_path(options)?;
            let _lock = registry_lock(&path).await?;
            let mut registry = load(&path).await?;
            registry.active_profile = None;
            save(&path, &registry).await?;
            let present = ENV_BUNDLE
                .iter()
                .any(|name| std::env::var_os(name).is_some());
            Ok(OperationOutput::result(
                "auth.logout",
                json!({"activeProfile": null, "environmentCredentialsPresent": present}),
            ))
        }
        AuthCommand::Login(args) => {
            if options.profile.is_some() {
                return Err(InvalidInput(
                    "login names its profile positionally; do not pass --profile or TK_PROFILE"
                        .into(),
                )
                .into());
            }
            let org = options
                .organization_id
                .ok_or_else(|| InvalidInput("login requires --organization-id".into()))?;
            let path = registry_path(options)?;
            if load(&path).await?.profiles.contains_key(&args.name) {
                return Err(InvalidInput(format!(
                    "profile {} already exists; use profile use to select it",
                    args.name
                ))
                .into());
            }
            let key_path = fs::canonicalize(args.api_key_file)
                .await
                .context("resolve credential path")?;
            let base_url = endpoint(options, DEFAULT_URL.into())?;
            let identity = build_turnkey_client(read_key(&key_path).await?, &base_url)?
                .get_whoami(GetWhoamiRequest {
                    organization_id: org.to_string(),
                })
                .await
                .map_err(anyhow::Error::new)
                .context("Turnkey API request failed")?;
            let _lock = registry_lock(&path).await?;
            let mut registry = load(&path).await?;
            if registry.profiles.contains_key(&args.name) {
                return Err(InvalidInput(format!(
                    "profile {} already exists; use profile use to select it",
                    args.name
                ))
                .into());
            }
            registry.profiles.insert(
                args.name.clone(),
                Profile {
                    organization_id: org,
                    api_base_url: base_url,
                    api_key_file: key_path,
                    ssh_signing_key_id: None,
                },
            );
            registry.active_profile = Some(args.name.clone());
            save(&path, &registry).await?;
            Ok(OperationOutput::result(
                "auth.login",
                json!({"profile": args.name, "identity": identity}),
            ))
        }
    }
}

pub async fn run_profile(
    command: ProfileCommand,
    options: &AuthOptions,
) -> Result<OperationOutput> {
    let path = registry_path(options)?;
    let _lock = if matches!(&command, ProfileCommand::List | ProfileCommand::Show { .. }) {
        None
    } else {
        Some(registry_lock(&path).await?)
    };
    let mut registry = load(&path).await?;
    match command {
        ProfileCommand::List => Ok(OperationOutput::result(
            "profile.list",
            json!({"activeProfile": registry.active_profile, "profiles": registry.profiles}),
        )),
        ProfileCommand::Show { name } => {
            let profile = registry
                .profiles
                .get(&name)
                .ok_or_else(|| profile_missing(&name))?;
            Ok(OperationOutput::result(
                "profile.show",
                json!({"name": name, "profile": profile}),
            ))
        }
        ProfileCommand::Use { name } => {
            let profile = registry
                .profiles
                .get(&name)
                .ok_or_else(|| profile_missing(&name))?;
            read_key(&profile.api_key_file).await?;
            registry.active_profile = Some(name.clone());
            save(&path, &registry).await?;
            Ok(OperationOutput::result(
                "profile.use",
                json!({"activeProfile": name}),
            ))
        }
        ProfileCommand::Delete { name } => {
            registry
                .profiles
                .remove(&name)
                .ok_or_else(|| profile_missing(&name))?;
            if registry.active_profile.as_ref() == Some(&name) {
                registry.active_profile = None;
            }
            save(&path, &registry).await?;
            Ok(OperationOutput::result(
                "profile.delete",
                json!({"name": name, "credentialFilesDeleted": false}),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sweep_removes_only_files_older_than_the_cutoff() {
        use std::time::{Duration, SystemTime};
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("org-a");
        std::fs::create_dir_all(&nested).unwrap();
        let stale = nested.join("stale.json");
        let fresh = nested.join("fresh.json");
        std::fs::write(&stale, b"{}").unwrap();
        std::fs::write(&fresh, b"{}").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(25 * 3600))
            .unwrap();

        let removed = sweep_stale(dir.path(), Duration::from_secs(24 * 3600))
            .await
            .unwrap();

        assert_eq!(removed, 1);
        assert!(!stale.exists());
        assert!(fresh.exists());
        assert_eq!(
            sweep_stale(&dir.path().join("does-not-exist"), Duration::from_secs(1))
                .await
                .unwrap(),
            0
        );
    }
}
