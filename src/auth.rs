use std::{
    collections::{BTreeMap, btree_map::Entry},
    fmt::{self, Display, Formatter},
    io::{self, ErrorKind},
    mem,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, PoisonError},
    time::{Duration, SystemTime},
};

use anyhow::{Context, Error, Result, bail};
use clap::{Args, Subcommand, builder::NonEmptyStringValueParser};
use reqwest::{Client, ClientBuilder, Url, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
};
use tracing::debug;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::{
    TurnkeyClient,
    generated::{GetWhoamiRequest, GetWhoamiResponse},
};
use uuid::Uuid;

use crate::{
    errors::{InvalidInput, Malformed, OrganizationMismatch},
    gpg::registry::{GpgKeyEntry, GpgKeyTable, KeyName, SelectError, SigningKeyName, StoredGpgKey},
    keygen::{GeneratedApiKey, generate},
    operations::OperationOutput,
    sessions::public_key::CompressedPublicKey,
    ssh::registry::{
        SelectError as SshSelectError, SshKeyEntry, SshKeyName, SshKeyTable, StoredSshKey,
    },
};

const DEFAULT_URL: &str = "https://api.turnkey.com";
const DEFAULT_PROFILE_NAME: &str = "default";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Args)]
pub struct AuthOptions {
    /// Named profile to use from the identity registry.
    ///
    /// An explicit profile always wins over the TURNKEY_* environment bundle.
    #[arg(long, global = true, env = "TK_PROFILE")]
    profile: Option<String>,
    /// Override the organization the command operates on.
    #[arg(long, global = true)]
    organization_id: Option<Uuid>,
    /// Override the API base URL.
    #[arg(long, global = true)]
    api_base_url: Option<String>,
}

impl AuthOptions {
    pub(crate) fn profile(&self) -> Option<&str> {
        self.profile.as_deref()
    }

    pub(crate) fn organization_id(&self) -> Option<Uuid> {
        self.organization_id
    }

    pub(crate) fn api_base_url(&self) -> Option<&str> {
        self.api_base_url.as_deref()
    }
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Verify a saved profile with Turnkey and select it.
    Login(LoginArgs),
    /// Inspect local credential readiness without contacting the server.
    Status,
    /// Verify the selected identity with Turnkey.
    Whoami,
    /// Clear the saved profile selection.
    ///
    /// Credential files and registered API keys are kept.
    Logout,
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Saved profile to verify and select.
    #[arg(
        long = "profile-name",
        default_value = DEFAULT_PROFILE_NAME,
        value_parser = NonEmptyStringValueParser::new()
    )]
    name: String,
}

#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// Save a new profile without contacting Turnkey.
    Create(CreateArgs),
    #[command(flatten)]
    Saved(SavedProfileCommand),
}

#[derive(Debug, Subcommand)]
pub enum SavedProfileCommand {
    /// List saved profiles and the active selection.
    List,
    /// Show one saved profile.
    Show {
        /// Saved profile to show.
        #[arg(long = "profile-name", value_parser = NonEmptyStringValueParser::new())]
        name: String,
    },
    /// Select a saved profile after checking its credential file.
    Use {
        /// Saved profile to select.
        #[arg(long = "profile-name", value_parser = NonEmptyStringValueParser::new())]
        name: String,
    },
    /// Remove a saved profile.
    ///
    /// Credential files are kept.
    Delete {
        /// Saved profile to remove.
        #[arg(long = "profile-name", value_parser = NonEmptyStringValueParser::new())]
        name: String,
    },
    /// Update a saved profile.
    Set {
        /// Saved profile to update.
        #[arg(long = "profile-name", value_parser = NonEmptyStringValueParser::new())]
        name: String,
        /// Existing P256 credential JSON file to use from now on.
        #[arg(long)]
        api_key_file: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Name for the new profile.
    #[arg(
        long = "profile-name",
        default_value = DEFAULT_PROFILE_NAME,
        value_parser = NonEmptyStringValueParser::new()
    )]
    name: String,
    /// Existing P256 credential JSON file to use; without it, a fresh
    /// credential is written under ~/.config/turnkey/tk/api-keys/.
    #[arg(long)]
    api_key_file: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
pub struct StoredApiKey {
    pub public_key: String,
    pub private_key: String,
    pub curve: KeyCurve,
}

#[derive(Serialize, Deserialize)]
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
    /// `OpenPGP` keys by fingerprint, shared by every profile because a key
    /// belongs to an organization.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    gpg_keys: BTreeMap<String, StoredGpgKey>,
    /// SSH keys by OpenSSH fingerprint.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    ssh_keys: BTreeMap<String, StoredSshKey>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            version: 1,
            active_profile: None,
            profiles: BTreeMap::new(),
            gpg_keys: BTreeMap::new(),
            ssh_keys: BTreeMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Profile {
    pub(crate) organization_id: Uuid,
    pub(crate) api_base_url: ApiBaseUrl,
    pub(crate) api_key_file: PathBuf,
}

#[derive(Debug)]
pub enum CredentialSource {
    Environment,
    Profile(String),
}

impl Display for CredentialSource {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Environment => "environment",
            Self::Profile(_) => "profile",
        })
    }
}

#[derive(Debug)]
pub enum SelectedIdentity {
    OrganizationIdFlag,
    Credential(CredentialSource),
}

impl Display for SelectedIdentity {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::OrganizationIdFlag => f.write_str("--organization-id"),
            Self::Credential(source) => Display::fmt(source, f),
        }
    }
}

/// An HTTP(S) origin, optionally with a path prefix, that carries no
/// credentials, query, or fragment. The text is kept exactly as supplied so
/// persisted and reported values match the input.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(test, derive(Debug))]
#[serde(try_from = "String")]
pub struct ApiBaseUrl(String);

impl Default for ApiBaseUrl {
    fn default() -> Self {
        Self(DEFAULT_URL.to_owned())
    }
}

impl Display for ApiBaseUrl {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for ApiBaseUrl {
    type Error = Error;

    fn try_from(raw: String) -> Result<Self> {
        let url =
            Url::parse(&raw).map_err(|error| Malformed::new("invalid API base URL", error))?;
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
        Ok(Self(raw))
    }
}

impl ApiBaseUrl {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub struct ResolvedAuth {
    pub org_id: Uuid,
    pub api_base_url: ApiBaseUrl,
    pub stamper: TurnkeyP256ApiKey,
    pub source: CredentialSource,
    pub http: OnceLock<Client>,
}

impl ResolvedAuth {
    pub fn http(&self) -> Result<&Client> {
        if let Some(client) = self.http.get() {
            return Ok(client);
        }
        let client = transport(Client::builder())
            .build()
            .context("could not initialize HTTP client")?;
        Ok(self.http.get_or_init(|| client))
    }
}

#[cfg(test)]
impl ResolvedAuth {
    pub fn for_tests(org_id: &str, api_base_url: &str, stamper: TurnkeyP256ApiKey) -> Self {
        Self {
            org_id: Uuid::parse_str(org_id).expect("test organization ID is a UUID"),
            api_base_url: ApiBaseUrl::try_from(api_base_url.to_owned())
                .expect("test API base URL is a valid HTTP(S) URL"),
            stamper,
            source: CredentialSource::Environment,
            http: OnceLock::new(),
        }
    }
}

fn transport(builder: ClientBuilder) -> ClientBuilder {
    builder.redirect(Policy::none()).timeout(REQUEST_TIMEOUT)
}

pub fn build_turnkey_client(
    stamper: TurnkeyP256ApiKey,
    api_base_url: &ApiBaseUrl,
) -> Result<TurnkeyClient<TurnkeyP256ApiKey>> {
    TurnkeyClient::builder()
        .api_key(stamper)
        .base_url(api_base_url.as_str())
        .with_reqwest_builder(transport)
        .build()
        .context("failed to build Turnkey client")
}

pub(crate) struct ReloadingClient {
    public_key: Vec<u8>,
    api_base_url: ApiBaseUrl,
    client: Arc<TurnkeyClient<TurnkeyP256ApiKey>>,
}

impl ReloadingClient {
    pub(crate) fn connect(auth: ResolvedAuth) -> Result<Self> {
        let public_key = auth.stamper.compressed_public_key();
        let client = build_turnkey_client(auth.stamper, &auth.api_base_url)?;
        Ok(Self {
            public_key,
            api_base_url: auth.api_base_url,
            client: Arc::new(client),
        })
    }

    pub(crate) fn client(&self) -> &Arc<TurnkeyClient<TurnkeyP256ApiKey>> {
        &self.client
    }

    pub(crate) async fn reload(
        cached: &Mutex<Self>,
        options: &AuthOptions,
        organization_id: Uuid,
    ) -> Result<Arc<TurnkeyClient<TurnkeyP256ApiKey>>> {
        let auth = LoadedRegistry::load()
            .await?
            .resolve_for_organization(options, organization_id)
            .await?;
        let mut cached = cached.lock().unwrap_or_else(PoisonError::into_inner);
        if auth.stamper.compressed_public_key() != cached.public_key
            || auth.api_base_url != cached.api_base_url
        {
            *cached = Self::connect(auth)?;
        }
        Ok(Arc::clone(&cached.client))
    }
}

pub(crate) async fn whoami(
    client: &TurnkeyClient<TurnkeyP256ApiKey>,
    organization_id: Uuid,
) -> Result<GetWhoamiResponse> {
    client
        .get_whoami(GetWhoamiRequest {
            organization_id: organization_id.to_string(),
        })
        .await
        .map_err(Error::new)
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

pub(crate) fn config_dir() -> Option<PathBuf> {
    env("HOME").map(|home| PathBuf::from(home).join(".config/turnkey"))
}

fn registry_path() -> Result<PathBuf> {
    Ok(config_dir()
        .context("HOME is required")?
        .join("tk.config.toml"))
}

pub(crate) fn state_dir() -> Result<PathBuf> {
    Ok(config_dir().context("HOME is required")?.join("tk"))
}

async fn sweep_stale(dir: &Path, max_age: Duration) -> io::Result<usize> {
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
    let malformed = |mut error: toml::de::Error| {
        // The registry may hold a pasted secret; keep the parser's message and
        // key path but never echo the document itself.
        error.set_input(None);
        Malformed::new(
            format!("invalid identity registry {}", path.display()),
            error,
        )
    };
    let RegistryVersion { version } = toml::from_str(&text).map_err(malformed)?;
    if version != 1 {
        bail!(
            "unsupported registry version {version} in {}",
            path.display()
        );
    }
    let registry: Registry = toml::from_str(&text).map_err(malformed)?;
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

struct FileLock {
    _file: fs::File,
}

#[derive(Debug, thiserror::Error)]
#[error("{resource} is locked by another tk process ({}); retry after it completes", lock.display())]
struct LockHeld {
    resource: String,
    lock: PathBuf,
}

impl FileLock {
    async fn acquire(lock: PathBuf, resource: &str) -> Result<Self> {
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
                let error = io::Error::last_os_error();
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
    Io(io::Error),
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

// The decode errors echo private credential bytes, which must not enter the error chain.
#[allow(clippy::map_err_ignore)]
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

pub(crate) async fn read_key(path: &Path) -> Result<TurnkeyP256ApiKey> {
    let text = fs::read_to_string(path)
        .await
        .with_context(|| format!("read credential {}", path.display()))?;
    let key: StoredApiKey = serde_json::from_str(&text).map_err(|error| {
        Malformed::new(
            format!("invalid credential JSON in {}", path.display()),
            error,
        )
    })?;
    parse_key(&key.private_key, &key.public_key)
}

pub(crate) fn endpoint_override(options: &AuthOptions) -> Result<Option<ApiBaseUrl>> {
    options
        .api_base_url
        .clone()
        .or_else(|| env("TURNKEY_API_BASE_URL"))
        .map(ApiBaseUrl::try_from)
        .transpose()
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
    let registry = LoadedRegistry::load().await?;
    resolve_in_registry(options, &registry.path, &registry.registry).await
}

pub struct LoadedRegistry {
    path: PathBuf,
    registry: Registry,
}

impl LoadedRegistry {
    pub async fn load() -> Result<Self> {
        let path = registry_path()?;
        let registry = load(&path).await?;
        Ok(Self { path, registry })
    }

    pub fn take_ssh_keys(&mut self) -> Result<SshKeyTable> {
        SshKeyTable::from_stored(mem::take(&mut self.registry.ssh_keys), &self.path)
    }

    fn take_gpg_keys(&mut self) -> Result<GpgKeyTable> {
        GpgKeyTable::from_stored(mem::take(&mut self.registry.gpg_keys), &self.path)
    }

    /// The organization explicitly selected for an agent snapshot, if any.
    pub fn explicit_organization(&self, options: &AuthOptions) -> Result<Option<(Uuid, String)>> {
        if let Some(organization_id) = options.organization_id {
            return Ok(Some((organization_id, "--organization-id".into())));
        }
        if let Some(name) = &options.profile {
            let profile = self
                .registry
                .profiles
                .get(name)
                .ok_or_else(|| profile_missing(name))?;
            return Ok(Some((profile.organization_id, format!("profile {name}"))));
        }
        if ENV_BUNDLE
            .iter()
            .any(|name| std::env::var_os(name).is_some())
        {
            let auth = resolve_environment(options)?.ok_or_else(|| {
                InvalidInput("the credential environment did not select an organization".into())
            })?;
            return Ok(Some((auth.org_id, "the environment bundle".into())));
        }
        Ok(None)
    }

    pub async fn resolve_for_organization(
        &self,
        options: &AuthOptions,
        organization_id: Uuid,
    ) -> Result<ResolvedAuth> {
        let mismatch = |actual, identity| OrganizationMismatch {
            expected: organization_id,
            actual,
            identity,
        };
        if let Some(actual) = options.organization_id
            && actual != organization_id
        {
            return Err(mismatch(actual, SelectedIdentity::OrganizationIdFlag).into());
        }
        let checked = |auth: ResolvedAuth| -> Result<ResolvedAuth> {
            if auth.org_id != organization_id {
                return Err(
                    mismatch(auth.org_id, SelectedIdentity::Credential(auth.source)).into(),
                );
            }
            Ok(auth)
        };
        if options.profile.is_some() {
            return checked(resolve_in_registry(options, &self.path, &self.registry).await?);
        }
        if let Some(auth) = resolve_environment(options)? {
            return checked(auth);
        }
        let active_profile = self.registry.active_profile.as_ref();
        let mut candidates: Vec<(&String, &Profile)> = self
            .registry
            .profiles
            .iter()
            .filter(|(_, profile)| profile.organization_id == organization_id)
            .collect();
        let chosen = match candidates.len() {
            0 => {
                return Err(InvalidInput(format!(
                    "no profile holds a credential for organization {organization_id}; run tk profile create --profile-name <name> --organization-id {organization_id}"
                ))
                .into());
            }
            1 => 0,
            _ => candidates
                .iter()
                .position(|(name, _)| Some(*name) == active_profile)
                .ok_or_else(|| {
                    let names: Vec<&str> = candidates.iter().map(|(name, _)| name.as_str()).collect();
                    InvalidInput(format!(
                        "profiles {} all hold a credential for organization {organization_id}; select one with --profile, TK_PROFILE, or tk profile use",
                        names.join(", ")
                    ))
                })?,
        };
        let (name, profile) = candidates.swap_remove(chosen);
        resolve_profile(options, name.clone(), profile).await
    }
}

async fn resolve_in_registry(
    options: &AuthOptions,
    path: &Path,
    registry: &Registry,
) -> Result<ResolvedAuth> {
    let name = options
        .profile
        .clone()
        .or_else(|| registry.active_profile.clone())
        .ok_or_else(|| InvalidInput("no selected identity; use --profile or tk login".into()))?;
    let profile = registry.profiles.get(&name).ok_or_else(|| {
        InvalidInput(format!(
            "profile {name} does not exist in {}",
            path.display()
        ))
    })?;
    resolve_profile(options, name, profile).await
}

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
        // The Err payload is the credential bytes, which must not enter the error chain.
        #[allow(clippy::map_err_ignore)]
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
            .map_err(|error| Malformed::new("invalid environment organization ID", error))?,
    };
    Ok(Some(ResolvedAuth {
        org_id: org,
        api_base_url: endpoint_override(options)?.unwrap_or_default(),
        stamper: parse_key(&private, &public)?,
        source: CredentialSource::Environment,
        http: OnceLock::new(),
    }))
}

async fn resolve_profile(
    options: &AuthOptions,
    name: String,
    profile: &Profile,
) -> Result<ResolvedAuth> {
    let Profile {
        organization_id,
        api_base_url,
        api_key_file,
    } = profile;
    Ok(ResolvedAuth {
        org_id: options.organization_id.unwrap_or(*organization_id),
        api_base_url: endpoint_override(options)?.unwrap_or_else(|| api_base_url.clone()),
        stamper: read_key(api_key_file).await?,
        source: CredentialSource::Profile(name),
        http: OnceLock::new(),
    })
}

pub(crate) async fn saved_profile(name: &str) -> Result<Profile> {
    let path = registry_path()?;
    load(&path)
        .await?
        .profiles
        .remove(name)
        .ok_or_else(|| profile_missing(name))
        .map_err(Into::into)
}

pub(crate) async fn remove_generated_key(path: &Path) -> bool {
    let removed: Result<bool> = async {
        let api_keys = state_dir()?.join("api-keys");
        let api_keys = fs::canonicalize(&api_keys).await.unwrap_or(api_keys);
        if !path.starts_with(&api_keys) {
            return Ok(false);
        }
        let registry_path = registry_path()?;
        let _lock = registry_lock(&registry_path).await?;
        let registry = load(&registry_path).await?;
        if registry
            .profiles
            .values()
            .any(|profile| profile.api_key_file == path)
        {
            return Ok(false);
        }
        fs::remove_file(path)
            .await
            .with_context(|| format!("remove {}", path.display()))?;
        Ok(true)
    }
    .await;
    removed.unwrap_or_else(|error| {
        debug!(%error, "generated key file was not removed");
        false
    })
}

fn profile_missing(name: &str) -> InvalidInput {
    InvalidInput(format!("profile {name} does not exist"))
}

pub async fn load_gpg_keys() -> Result<GpgKeyTable> {
    LoadedRegistry::load().await?.take_gpg_keys()
}

pub async fn open_gpg_key(
    options: &AuthOptions,
    key: Option<KeyName>,
) -> Result<Result<(GpgKeyEntry, TurnkeyClient<TurnkeyP256ApiKey>), SelectError>> {
    let (entry, auth) = match resolve_gpg_key(options, key).await? {
        Ok(resolved) => resolved,
        Err(error) => return Ok(Err(error)),
    };
    let client = build_turnkey_client(auth.stamper, &auth.api_base_url)?;
    Ok(Ok((entry, client)))
}

pub async fn resolve_gpg_key(
    options: &AuthOptions,
    key: Option<KeyName>,
) -> Result<Result<(GpgKeyEntry, ResolvedAuth), SelectError>> {
    let mut registry = LoadedRegistry::load().await?;
    let entry = match registry.take_gpg_keys()?.select(key) {
        Ok(entry) => entry,
        Err(error) => return Ok(Err(error)),
    };
    let auth = registry
        .resolve_for_organization(options, entry.organization_id)
        .await
        .with_context(|| {
            format!(
                "select a credential for OpenPGP key {}",
                entry.fingerprint()
            )
        })?;
    Ok(Ok((entry, auth)))
}

pub async fn register_gpg_key(entry: GpgKeyEntry) -> Result<()> {
    let path = registry_path()?;
    let _lock = registry_lock(&path).await?;
    let mut registry = load(&path).await?;
    let mut table = GpgKeyTable::from_stored(registry.gpg_keys, &path)?;
    table.insert(entry);
    registry.gpg_keys = table.into_stored();
    save(&path, &registry).await
}

pub async fn remove_gpg_key(name: SigningKeyName) -> Result<Result<GpgKeyEntry, SelectError>> {
    let path = registry_path()?;
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

/// Reading the SSH table needs no credential.
pub async fn load_ssh_keys() -> Result<SshKeyTable> {
    LoadedRegistry::load().await?.take_ssh_keys()
}

pub async fn open_ssh_key(
    options: &AuthOptions,
    key: Option<SshKeyName>,
) -> Result<Result<(SshKeyEntry, TurnkeyClient<TurnkeyP256ApiKey>), SshSelectError>> {
    let mut registry = LoadedRegistry::load().await?;
    let entry = match registry.take_ssh_keys()?.select(key) {
        Ok(entry) => entry,
        Err(error) => return Ok(Err(error)),
    };
    let auth = registry
        .resolve_for_organization(options, entry.organization_id)
        .await
        .with_context(|| format!("select a credential for SSH key {}", entry.fingerprint()))?;
    let client = build_turnkey_client(auth.stamper, &auth.api_base_url)?;
    Ok(Ok((entry, client)))
}

pub async fn register_ssh_key(entry: SshKeyEntry) -> Result<()> {
    let path = registry_path()?;
    let _lock = registry_lock(&path).await?;
    let mut registry = load(&path).await?;
    let mut table = SshKeyTable::from_stored(registry.ssh_keys, &path)?;
    table.insert(entry);
    registry.ssh_keys = table.into_stored();
    save(&path, &registry).await
}

pub async fn remove_ssh_key(name: SshKeyName) -> Result<Result<SshKeyEntry, SshSelectError>> {
    let path = registry_path()?;
    let _lock = registry_lock(&path).await?;
    let mut registry = load(&path).await?;
    let mut table = SshKeyTable::from_stored(registry.ssh_keys, &path)?;
    let removed = match table.remove(name) {
        Ok(entry) => entry,
        Err(error) => return Ok(Err(error)),
    };
    registry.ssh_keys = table.into_stored();
    save(&path, &registry).await?;
    Ok(Ok(removed))
}

pub async fn run_auth(command: AuthCommand, options: &AuthOptions) -> Result<OperationOutput> {
    match command {
        AuthCommand::Status => {
            let auth = resolve(options).await?;
            let source = auth.source.to_string();
            let profile = match &auth.source {
                CredentialSource::Environment => None,
                CredentialSource::Profile(name) => Some(name),
            };
            Ok(OperationOutput::result(
                "auth.status",
                json!({"ready": true, "profile": profile, "organizationId": auth.org_id, "apiBaseUrl": auth.api_base_url, "publicKey": hex::encode(auth.stamper.compressed_public_key()), "credentialSource": source}),
            ))
        }
        AuthCommand::Whoami => {
            let auth = resolve(options).await?;
            let client = build_turnkey_client(auth.stamper, &auth.api_base_url)?;
            let identity = whoami(&client, auth.org_id)
                .await
                .context("Turnkey API request failed")?;
            Ok(OperationOutput::result(
                "auth.whoami",
                serde_json::to_value(identity)?,
            ))
        }
        AuthCommand::Logout => {
            let path = registry_path()?;
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
        AuthCommand::Login(args) => login(args, options).await,
    }
}

async fn login(args: LoginArgs, options: &AuthOptions) -> Result<OperationOutput> {
    let LoginArgs { name } = args;
    if options.profile.is_some() {
        return Err(InvalidInput(
            "login selects a profile with --profile-name; do not pass --profile or TK_PROFILE"
                .into(),
        )
        .into());
    }
    let path = registry_path()?;
    let Some(profile) = load(&path).await?.profiles.remove(&name) else {
        return Err(InvalidInput(format!(
            "profile {name} does not exist; run tk profile create --profile-name {name} --organization-id <org>"
        ))
        .into());
    };
    let Profile {
        organization_id,
        api_base_url,
        api_key_file,
    } = &profile;
    if let Some(requested) = options.organization_id
        && requested != *organization_id
    {
        return Err(InvalidInput(format!(
            "profile {name} is saved with organization {organization_id}; run tk profile set --profile-name {name} --organization-id {requested} to change it"
        ))
        .into());
    }
    if let Some(requested) = endpoint_override(options)?
        && requested != *api_base_url
    {
        return Err(InvalidInput(format!(
            "profile {name} is saved with API base URL {api_base_url}; run tk profile set --profile-name {name} --api-base-url {requested} to change it"
        ))
        .into());
    }
    let client = build_turnkey_client(read_key(api_key_file).await?, api_base_url)?;
    let identity = whoami(&client, *organization_id)
        .await
        .context("Turnkey API request failed")?;
    let _lock = registry_lock(&path).await?;
    let mut registry = load(&path).await?;
    let current = registry
        .profiles
        .get(&name)
        .ok_or_else(|| profile_missing(&name))?;
    if *current != profile {
        return Err(InvalidInput(format!(
            "profile {name} changed during login; run tk login --profile-name {name} again"
        ))
        .into());
    }
    let record = json!({"profile": name, "identity": identity});
    registry.active_profile = Some(name);
    save(&path, &registry).await?;
    Ok(OperationOutput::result("auth.login", record))
}

pub async fn create_profile(
    args: CreateArgs,
    organization_id: Uuid,
    api_base_url: ApiBaseUrl,
) -> Result<OperationOutput> {
    let CreateArgs { name, api_key_file } = args;
    let path = registry_path()?;
    let _lock = registry_lock(&path).await?;
    let mut registry = load(&path).await?;
    let slot = match registry.profiles.entry(name) {
        Entry::Occupied(existing) => {
            let name = existing.key();
            return Err(InvalidInput(format!(
                "profile {name} already exists; run tk login --profile-name {name} to select it"
            ))
            .into());
        }
        Entry::Vacant(slot) => slot,
    };
    let (api_key_file, public_key, generated) = match api_key_file {
        Some(file) => {
            let resolved = fs::canonicalize(&file)
                .await
                .context("resolve credential path")?;
            let key = read_key(&resolved).await?;
            (resolved, CompressedPublicKey::from(&key), None)
        }
        None => {
            let GeneratedApiKey { public_key, path } = generate(None).await?;
            (path.clone(), public_key, Some(path))
        }
    };
    let profile = Profile {
        organization_id,
        api_base_url,
        api_key_file,
    };
    let name = slot.key();
    let record = json!({
        "name": name,
        "profile": profile,
        "publicKey": public_key,
        "nextStep": format!("register public key {public_key} (API_KEY_CURVE_P256) on a user in organization {organization_id}, then run tk login --profile-name {name}"),
    });
    slot.insert(profile);
    if let Err(error) = save(&path, &registry).await {
        if let Some(generated) = generated {
            let _ = fs::remove_file(generated).await;
        }
        return Err(error);
    }
    Ok(OperationOutput::result("profile.create", record))
}

pub(crate) async fn set_profile_key(name: &str, api_key_file: PathBuf) -> Result<PathBuf> {
    let path = registry_path()?;
    let _lock = registry_lock(&path).await?;
    let mut registry = load(&path).await?;
    let profile = registry
        .profiles
        .get_mut(name)
        .ok_or_else(|| profile_missing(name))?;
    let previous = mem::replace(&mut profile.api_key_file, api_key_file);
    save(&path, &registry).await?;
    Ok(previous)
}

pub async fn run_profile(
    command: SavedProfileCommand,
    options: &AuthOptions,
) -> Result<OperationOutput> {
    let path = registry_path()?;
    let _lock = if matches!(
        &command,
        SavedProfileCommand::List | SavedProfileCommand::Show { .. }
    ) {
        None
    } else {
        Some(registry_lock(&path).await?)
    };
    let mut registry = load(&path).await?;
    match command {
        SavedProfileCommand::List => Ok(OperationOutput::result(
            "profile.list",
            json!({"activeProfile": registry.active_profile, "profiles": registry.profiles}),
        )),
        SavedProfileCommand::Show { name } => {
            let profile = registry
                .profiles
                .get(&name)
                .ok_or_else(|| profile_missing(&name))?;
            Ok(OperationOutput::result(
                "profile.show",
                json!({"name": name, "profile": profile}),
            ))
        }
        SavedProfileCommand::Use { name } => {
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
        SavedProfileCommand::Delete { name } => {
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
        SavedProfileCommand::Set { name, api_key_file } => {
            let profile = registry
                .profiles
                .get_mut(&name)
                .ok_or_else(|| profile_missing(&name))?;
            if let Some(organization_id) = options.organization_id {
                profile.organization_id = organization_id;
            }
            if let Some(api_base_url) = &options.api_base_url {
                profile.api_base_url = ApiBaseUrl::try_from(api_base_url.clone())?;
            }
            let mut record = json!({"name": name});
            if let Some(api_key_file) = api_key_file {
                let current = match fs::canonicalize(&api_key_file).await {
                    Ok(current) => current,
                    Err(error) if error.kind() == ErrorKind::NotFound => {
                        return Err(InvalidInput(format!(
                            "credential file {} does not exist",
                            api_key_file.display()
                        ))
                        .into());
                    }
                    Err(error) => return Err(error).context("resolve credential path"),
                };
                let key = read_key(&current).await?;
                let previous = mem::replace(&mut profile.api_key_file, current);
                record["publicKey"] = CompressedPublicKey::from(&key).to_string().into();
                record["previousApiKeyFile"] = previous.to_string_lossy().into();
            }
            record["profile"] = serde_json::to_value(&*profile)?;
            save(&path, &registry).await?;
            Ok(OperationOutput::result("profile.set", record))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_api_base_url_parses() {
        assert_eq!(
            ApiBaseUrl::default(),
            ApiBaseUrl::try_from(DEFAULT_URL.to_owned()).unwrap()
        );
    }

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
