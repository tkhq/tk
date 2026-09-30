use std::{
    convert::Infallible,
    fs,
    io::{self, Read},
    path::PathBuf,
    str::FromStr,
};

use anyhow::{Context, Result};
use clap::{ArgGroup, Args, Subcommand, ValueEnum};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, from_slice, to_value};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::generated::{
    external::data::v1::{ApiKey, Tag},
    immutable::{activity::v1 as intent, common::v1 as common},
    services::coordinator::public::v1 as query,
};
use uuid::Uuid;

use crate::{
    auth::{ResolvedAuth, build_turnkey_client},
    errors::{ActivityError, ActivityErrorKind, InvalidInput, Malformed, MissingResource},
    operations::{OperationOutput, query as query_api, submit_activity, unix_now},
    sessions::{duration::ExpiresIn, public_key::CompressedPublicKey},
};

#[derive(Debug, Subcommand)]
pub enum UserCommand {
    /// List users.
    List {
        /// Keep only users carrying this tag, given as a tag ID or an exact tag name.
        #[arg(long, value_name = "NAME_OR_ID")]
        tag: Option<TagSelector>,
    },
    /// Fetch one user by ID.
    Get {
        /// User ID.
        #[arg(long)]
        id: Uuid,
    },
    /// Create a user from flags, or one or more users from a
    /// `CreateUsersIntentV4` parameters object.
    Create(CreateUserArgs),
    /// Update a user from an `UpdateUserIntentV2` parameters object.
    Update(BodyArgs),
    /// Delete users by ID.
    Delete {
        /// User IDs.
        #[arg(long = "id", required = true)]
        ids: Vec<Uuid>,
    },
    /// Manage user tags.
    Tag {
        #[command(subcommand)]
        command: TagCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum TagCommand {
    /// List user tags.
    List,
    /// Create a tag by name, or from a `CreateUserTagIntent` parameters object.
    Create(CreateTagArgs),
    /// Update a tag from an `UpdateUserTagIntent` parameters object.
    Update(BodyArgs),
    /// Delete tags by ID.
    Delete {
        /// Tag IDs.
        #[arg(long = "id", required = true)]
        ids: Vec<Uuid>,
    },
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// List policies.
    List,
    /// Fetch one policy by ID.
    Get {
        /// Policy ID.
        #[arg(long)]
        id: Uuid,
    },
    /// Create a policy from flags, or from a `CreatePolicyIntentV3` parameters
    /// object.
    Create(CreatePolicyArgs),
    /// Create multiple policies from a parameters object containing policies.
    CreateBatch(BodyArgs),
    /// Update a policy from an `UpdatePolicyIntentV2` parameters object.
    Update(BodyArgs),
    /// Delete policies by ID.
    Delete {
        /// Policy IDs.
        #[arg(long = "id", required = true)]
        ids: Vec<Uuid>,
    },
    /// List the policy evaluations recorded for one activity.
    Evaluations {
        /// Activity ID.
        #[arg(long)]
        activity_id: Uuid,
    },
}

#[derive(Debug, Clone)]
pub enum TagSelector {
    Id(Uuid),
    Name(String),
}

impl FromStr for TagSelector {
    type Err = Infallible;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Ok(text
            .parse::<Uuid>()
            .map_or_else(|_| Self::Name(text.to_owned()), Self::Id))
    }
}

#[derive(Debug, Subcommand)]
pub enum ApiKeyCommand {
    /// List API keys.
    List(ApiKeyListArgs),
    /// Register public keys from a `CreateApiKeysIntentV2` parameters object.
    Register(BodyArgs),
    /// Delete API keys of one user by ID.
    Delete {
        /// User who owns the keys.
        #[arg(long)]
        user_id: Uuid,
        /// API key IDs.
        #[arg(long = "id", required = true)]
        ids: Vec<Uuid>,
    },
}

#[derive(Debug, Args)]
#[group(skip)]
#[command(group(ArgGroup::new("body_source").required(true).multiple(false).args(["input_json", "input_file"])))]
pub struct BodyArgs {
    #[command(flatten)]
    body: BodySource,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("owner").required(true).args(["user_id", "all_users"])))]
#[command(group(ArgGroup::new("expiry").args(["expiring_within", "expired", "long_lived"])))]
pub struct ApiKeyListArgs {
    /// List the keys of this user.
    #[arg(long)]
    user_id: Option<Uuid>,
    /// List the keys of every user in the organization.
    #[arg(long)]
    all_users: bool,
    /// Keep only keys whose expiry is at most this far ahead, such as 2h or 7d.
    #[arg(long, value_name = "DURATION")]
    expiring_within: Option<ExpiresIn>,
    /// Keep only keys whose expiry has passed.
    #[arg(long)]
    expired: bool,
    /// Keep only keys that never expire.
    #[arg(long)]
    long_lived: bool,
}

pub enum KeyOwner {
    User(Uuid),
    AllUsers,
}

pub enum ExpiryFilter {
    ExpiresBy(u64),
    LongLived,
}

#[derive(Debug, Args)]
#[group(skip)]
struct BodySource {
    /// Inline JSON parameters (no activity envelope).
    #[arg(long)]
    input_json: Option<String>,
    /// Read JSON parameters from a file, or - for stdin.
    #[arg(long)]
    input_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("user_source").required(true).args(["input_json", "input_file", "user_name"])))]
pub struct CreateUserArgs {
    #[command(flatten)]
    body: BodySource,
    /// Name of the single user to create.
    #[arg(long)]
    user_name: Option<String>,
    /// Email of the user.
    #[arg(long, requires = "user_name")]
    email: Option<String>,
    /// Tag ID to attach.
    #[arg(long = "tag", requires = "user_name")]
    tags: Vec<Uuid>,
    /// Tag name to attach, resolved against the organization's tags.
    #[arg(long = "tag-name", requires = "user_name")]
    tag_names: Vec<String>,
    /// Compressed P256 public key (hex) to register as the user's API key.
    #[arg(long, requires = "user_name")]
    public_key: Option<CompressedPublicKey>,
    /// Lifetime of that API key, for example 7d; omit for a key that never expires.
    #[arg(long, requires = "public_key")]
    expires_in: Option<ExpiresIn>,
    /// Also register a never-expiring anchor key whose private half is
    /// generated here and discarded.
    ///
    /// Turnkey requires every user to hold one long-lived credential; the
    /// anchor key satisfies that so the user can otherwise live on expiring
    /// keys alone.
    #[arg(long, requires = "user_name")]
    anchor_key: bool,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("tag_source").required(true).args(["input_json", "input_file", "name"])))]
pub struct CreateTagArgs {
    #[command(flatten)]
    body: BodySource,
    /// Name of the new tag, with no members.
    #[arg(long)]
    name: Option<String>,
}

#[derive(Clone, Debug, ValueEnum)]
enum EffectArg {
    Allow,
    Deny,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("policy_source").required(true).args(["input_json", "input_file", "name"])))]
#[command(group(ArgGroup::new("rule").args(["condition", "consensus"]).multiple(true)))]
pub struct CreatePolicyArgs {
    #[command(flatten)]
    body: BodySource,
    /// Name of the policy.
    #[arg(long, requires_all = ["effect", "rule"])]
    name: Option<String>,
    /// Effect of the policy.
    #[arg(long, value_enum, requires = "name")]
    effect: Option<EffectArg>,
    /// Condition expression, evaluated against the activity.
    #[arg(long, requires = "name")]
    condition: Option<String>,
    /// Consensus expression, evaluated against the approvers.
    #[arg(long, requires = "name")]
    consensus: Option<String>,
    /// Free-text notes stored with the policy.
    #[arg(long, requires = "name")]
    notes: Option<String>,
}

pub enum PreparedResource {
    Query(Query),
    Mutation(Mutation),
}

pub enum Query {
    Users {
        tag: Option<TagSelector>,
    },
    User(Uuid),
    Tags,
    Policies,
    Policy(Uuid),
    Evaluations(Uuid),
    ApiKeys {
        owner: KeyOwner,
        expiry: Option<ExpiryFilter>,
    },
}

pub enum Mutation {
    CreateUsers(intent::CreateUsersIntentV4),
    CreateUser {
        user: intent::UserParamsV4,
        tag_names: Vec<String>,
    },
    UpdateUser(intent::UpdateUserIntent),
    DeleteUsers(intent::DeleteUsersIntent),
    CreateTag(intent::CreateUserTagIntent),
    UpdateTag(intent::UpdateUserTagIntent),
    DeleteTags(intent::DeleteUserTagsIntent),
    CreatePolicy(intent::CreatePolicyIntentV3),
    CreatePolicies(intent::CreatePoliciesIntent),
    UpdatePolicy(intent::UpdatePolicyIntentV2),
    DeletePolicy(intent::DeletePolicyIntent),
    DeletePolicies(intent::DeletePoliciesIntent),
    RegisterKeys(intent::CreateApiKeysIntentV2),
    DeleteKeys(intent::DeleteApiKeysIntent),
}

impl BodyArgs {
    pub(crate) fn parse<T: DeserializeOwned + Serialize>(self) -> Result<T> {
        self.body.parse()
    }
}

impl BodySource {
    fn parse<T: DeserializeOwned + Serialize>(self) -> Result<T> {
        let bytes = match (self.input_json, self.input_file) {
            (Some(json), _) => json.into_bytes(),
            (None, Some(path)) if path.as_os_str() == "-" => {
                let mut bytes = Vec::new();
                io::stdin().read_to_end(&mut bytes).map_err(|error| {
                    Malformed::new("could not read JSON parameters from stdin", error)
                })?;
                bytes
            }
            (None, Some(path)) => fs::read(&path).map_err(|error| {
                Malformed::new(
                    format!("could not read JSON parameters from {}", path.display()),
                    error,
                )
            })?,
            (None, None) => unreachable!("clap requires exactly one parameters source"),
        };
        let mut value: Value = from_slice(&bytes)
            .map_err(|error| Malformed::new("parameters must be valid JSON", error))?;
        if !value.is_object() {
            return Err(InvalidInput("parameters must be a JSON object".into()).into());
        }
        normalize_ids(&mut value)?;
        let typed: T = T::deserialize(&value)
            .map_err(|error| Malformed::new("invalid operation parameters", error))?;
        let normalized = to_value(&typed)?;
        reject_dropped_fields(&value, &normalized, "parameters")?;
        Ok(typed)
    }
}

fn normalize_id(value: &mut Value, key: &str) -> Result<()> {
    let Some(id) = value.as_str() else {
        return Err(InvalidInput(format!("{key} must be a string")).into());
    };
    let id = Uuid::parse_str(id)
        .map_err(|error| Malformed::new(format!("invalid UUID in {key}"), error))?;
    *value = Value::String(id.to_string());
    Ok(())
}

fn normalize_ids(value: &mut Value) -> Result<()> {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                if matches!(key.as_str(), "userId" | "userTagId" | "policyId") {
                    normalize_id(value, key)?;
                } else if matches!(
                    key.as_str(),
                    "userIds"
                        | "userTags"
                        | "userTagIds"
                        | "addUserIds"
                        | "removeUserIds"
                        | "apiKeyIds"
                        | "policyIds"
                ) {
                    let Some(ids) = value.as_array_mut() else {
                        return Err(InvalidInput(format!("{key} must be an array")).into());
                    };
                    for value in ids {
                        normalize_id(value, key)?;
                    }
                } else {
                    normalize_ids(value)?;
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                normalize_ids(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn reject_dropped_fields(input: &Value, normalized: &Value, path: &str) -> Result<()> {
    match (input, normalized) {
        (Value::Object(input), Value::Object(normalized)) => {
            for (key, value) in input {
                let Some(known) = normalized.get(key) else {
                    return Err(InvalidInput(format!("unsupported field {path}.{key}")).into());
                };
                reject_dropped_fields(value, known, &format!("{path}.{key}"))?;
            }
        }
        (Value::Array(input), Value::Array(normalized)) => {
            for (i, (value, known)) in input.iter().zip(normalized).enumerate() {
                reject_dropped_fields(value, known, &format!("{path}[{i}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

impl UserCommand {
    pub fn prepare(self) -> Result<PreparedResource> {
        Ok(match self {
            UserCommand::List { tag } => PreparedResource::Query(Query::Users { tag }),
            UserCommand::Get { id } => PreparedResource::Query(Query::User(id)),
            UserCommand::Create(CreateUserArgs {
                body,
                user_name: None,
                ..
            }) => {
                let params: intent::CreateUsersIntentV4 = body.parse()?;
                if params.users.is_empty() {
                    return Err(InvalidInput("users must contain at least one user".into()).into());
                }
                PreparedResource::Mutation(Mutation::CreateUsers(params))
            }
            UserCommand::Create(CreateUserArgs {
                user_name: Some(user_name),
                email,
                tags,
                tag_names,
                public_key,
                expires_in,
                anchor_key,
                ..
            }) => {
                let anchor = anchor_key.then(|| intent::ApiKeyParamsV2 {
                    api_key_name: format!("{user_name}-anchor"),
                    public_key: CompressedPublicKey::from(&TurnkeyP256ApiKey::generate())
                        .to_string(),
                    curve_type: common::ApiKeyCurve::P256,
                    expiration_seconds: None,
                });
                let api_keys = anchor
                    .into_iter()
                    .chain(public_key.map(|public_key| intent::ApiKeyParamsV2 {
                        api_key_name: format!("{user_name}-key"),
                        public_key: public_key.to_string(),
                        curve_type: common::ApiKeyCurve::P256,
                        expiration_seconds:
                            expires_in.map(|expires_in| expires_in.seconds().to_string()),
                    }))
                    .collect();
                let user = intent::UserParamsV4 {
                    user_name,
                    user_email: email,
                    user_phone_number: None,
                    api_keys,
                    authenticators: vec![],
                    oauth_providers: vec![],
                    user_tags: tags.iter().map(ToString::to_string).collect(),
                };
                PreparedResource::Mutation(Mutation::CreateUser { user, tag_names })
            }
            UserCommand::Update(body) => {
                PreparedResource::Mutation(Mutation::UpdateUser(body.parse()?))
            }
            UserCommand::Delete { ids } => {
                PreparedResource::Mutation(Mutation::DeleteUsers(intent::DeleteUsersIntent {
                    user_ids: ids.into_iter().map(|id| id.to_string()).collect(),
                }))
            }
            UserCommand::Tag { command } => match command {
                TagCommand::List => PreparedResource::Query(Query::Tags),
                TagCommand::Create(CreateTagArgs {
                    name: Some(user_tag_name),
                    ..
                }) => {
                    PreparedResource::Mutation(Mutation::CreateTag(intent::CreateUserTagIntent {
                        user_tag_name,
                        user_ids: vec![],
                    }))
                }
                TagCommand::Create(CreateTagArgs { body, name: None }) => {
                    PreparedResource::Mutation(Mutation::CreateTag(body.parse()?))
                }
                TagCommand::Update(body) => {
                    PreparedResource::Mutation(Mutation::UpdateTag(body.parse()?))
                }
                TagCommand::Delete { ids } => {
                    PreparedResource::Mutation(Mutation::DeleteTags(intent::DeleteUserTagsIntent {
                        user_tag_ids: ids.into_iter().map(|id| id.to_string()).collect(),
                    }))
                }
            },
        })
    }
}

impl PolicyCommand {
    pub fn prepare(self) -> Result<PreparedResource> {
        Ok(match self {
            PolicyCommand::List => PreparedResource::Query(Query::Policies),
            PolicyCommand::Get { id } => PreparedResource::Query(Query::Policy(id)),
            PolicyCommand::Create(CreatePolicyArgs {
                name: Some(policy_name),
                effect: Some(effect),
                condition,
                consensus,
                notes,
                ..
            }) => {
                PreparedResource::Mutation(Mutation::CreatePolicy(intent::CreatePolicyIntentV3 {
                    policy_name,
                    effect: match effect {
                        EffectArg::Allow => common::Effect::Allow,
                        EffectArg::Deny => common::Effect::Deny,
                    },
                    condition,
                    consensus,
                    notes: notes.unwrap_or_default(),
                    time: None,
                }))
            }
            PolicyCommand::Create(CreatePolicyArgs {
                body, name: None, ..
            }) => PreparedResource::Mutation(Mutation::CreatePolicy(body.parse()?)),
            PolicyCommand::Create(CreatePolicyArgs {
                name: Some(_),
                effect: None,
                ..
            }) => unreachable!("clap requires --effect with --name"),
            PolicyCommand::CreateBatch(body) => {
                let params: intent::CreatePoliciesIntent = body.parse()?;
                if params.policies.is_empty() {
                    return Err(
                        InvalidInput("policies must contain at least one policy".into()).into(),
                    );
                }
                PreparedResource::Mutation(Mutation::CreatePolicies(params))
            }
            PolicyCommand::Update(body) => {
                PreparedResource::Mutation(Mutation::UpdatePolicy(body.parse()?))
            }
            PolicyCommand::Delete { ids } => match ids.as_slice() {
                [only] => {
                    PreparedResource::Mutation(Mutation::DeletePolicy(intent::DeletePolicyIntent {
                        policy_id: only.to_string(),
                    }))
                }
                many => PreparedResource::Mutation(Mutation::DeletePolicies(
                    intent::DeletePoliciesIntent {
                        policy_ids: many.iter().map(ToString::to_string).collect(),
                    },
                )),
            },
            PolicyCommand::Evaluations { activity_id } => {
                PreparedResource::Query(Query::Evaluations(activity_id))
            }
        })
    }
}

impl ApiKeyCommand {
    pub fn prepare(self) -> Result<PreparedResource> {
        Ok(match self {
            ApiKeyCommand::List(ApiKeyListArgs {
                user_id,
                all_users: _,
                expiring_within,
                expired,
                long_lived,
            }) => {
                let owner = match user_id {
                    Some(id) => KeyOwner::User(id),
                    None => KeyOwner::AllUsers,
                };
                let expiry = match (expiring_within, expired, long_lived) {
                    (None, false, true) => Some(ExpiryFilter::LongLived),
                    (None, false, false) => None,
                    (within, _, _) => {
                        let now_ms = u64::try_from(unix_now()?.as_millis())
                            .context("current time exceeds the Unix millisecond range")?;
                        let ahead_ms = within.map_or(0, |within| within.seconds() * 1000);
                        Some(ExpiryFilter::ExpiresBy(now_ms.saturating_add(ahead_ms)))
                    }
                };
                PreparedResource::Query(Query::ApiKeys { owner, expiry })
            }
            ApiKeyCommand::Register(body) => {
                let params: intent::CreateApiKeysIntentV2 = body.parse()?;
                if params.api_keys.is_empty() {
                    return Err(InvalidInput(
                        "apiKeys must contain at least one public key".into(),
                    )
                    .into());
                }
                PreparedResource::Mutation(Mutation::RegisterKeys(params))
            }
            ApiKeyCommand::Delete { user_id, ids } => {
                PreparedResource::Mutation(Mutation::DeleteKeys(intent::DeleteApiKeysIntent {
                    user_id: user_id.to_string(),
                    api_key_ids: ids.into_iter().map(|id| id.to_string()).collect(),
                }))
            }
        })
    }
}

pub(crate) fn expires_at_unix_ms(key: &ApiKey) -> Result<Option<u64>> {
    let Some(lifetime) = key.expiration_seconds else {
        return Ok(None);
    };
    let created = key.created_at.as_ref().ok_or_else(|| {
        ActivityError::new(
            ActivityErrorKind::MalformedResponse,
            "get_api_keys returned an expiring apiKeys[] entry without createdAt",
        )
    })?;
    let created: u64 = created.seconds.parse().map_err(|error| {
        Malformed::new(
            format!(
                "get_api_keys returned a non-numeric apiKeys[].createdAt.seconds: {:?}",
                created.seconds
            ),
            error,
        )
    })?;
    let at_ms = (u128::from(created) + u128::from(lifetime)) * 1000;
    let at_ms = u64::try_from(at_ms).map_err(|error| {
        Malformed::new(
            "get_api_keys returned apiKeys[].createdAt.seconds plus apiKeys[].expirationSeconds beyond the unix millisecond range",
            error,
        )
    })?;
    Ok(Some(at_ms))
}

impl PreparedResource {
    pub async fn run(self, auth: ResolvedAuth) -> Result<OperationOutput> {
        match self {
            Self::Query(query) => query.run(auth).await,
            Self::Mutation(mutation) => mutation.run(auth).await,
        }
    }
}

impl Mutation {
    async fn run(self, auth: ResolvedAuth) -> Result<OperationOutput> {
        let (command, endpoint, kind, params) = match self {
            Self::CreateUsers(p) => (
                "user.create",
                "create_users",
                "ACTIVITY_TYPE_CREATE_USERS_V4",
                to_value(p)?,
            ),
            Self::CreateUser {
                mut user,
                tag_names,
            } => {
                if !tag_names.is_empty() {
                    let listed: query::ListUserTagsResponse = query_api(
                        "/public/v1/query/list_user_tags",
                        &query::ListUserTagsRequest {
                            organization_id: auth.org_id.to_string(),
                        },
                        &auth,
                    )
                    .await?;
                    for name in tag_names {
                        user.user_tags
                            .push(resolve_tag_name(&listed.user_tags, name)?.to_owned());
                    }
                }
                (
                    "user.create",
                    "create_users",
                    "ACTIVITY_TYPE_CREATE_USERS_V4",
                    to_value(intent::CreateUsersIntentV4 { users: vec![user] })?,
                )
            }
            Self::UpdateUser(p) => (
                "user.update",
                "update_user",
                "ACTIVITY_TYPE_UPDATE_USER",
                to_value(p)?,
            ),
            Self::DeleteUsers(p) => (
                "user.delete",
                "delete_users",
                "ACTIVITY_TYPE_DELETE_USERS",
                to_value(p)?,
            ),
            Self::CreateTag(p) => (
                "user.tag.create",
                "create_user_tag",
                "ACTIVITY_TYPE_CREATE_USER_TAG",
                to_value(p)?,
            ),
            Self::UpdateTag(p) => (
                "user.tag.update",
                "update_user_tag",
                "ACTIVITY_TYPE_UPDATE_USER_TAG",
                to_value(p)?,
            ),
            Self::DeleteTags(p) => (
                "user.tag.delete",
                "delete_user_tags",
                "ACTIVITY_TYPE_DELETE_USER_TAGS",
                to_value(p)?,
            ),
            Self::CreatePolicy(p) => (
                "policy.create",
                "create_policy",
                "ACTIVITY_TYPE_CREATE_POLICY_V3",
                to_value(p)?,
            ),
            Self::CreatePolicies(p) => (
                "policy.create-batch",
                "create_policies",
                "ACTIVITY_TYPE_CREATE_POLICIES",
                to_value(p)?,
            ),
            Self::UpdatePolicy(p) => (
                "policy.update",
                "update_policy",
                "ACTIVITY_TYPE_UPDATE_POLICY_V2",
                to_value(p)?,
            ),
            Self::DeletePolicy(p) => (
                "policy.delete",
                "delete_policy",
                "ACTIVITY_TYPE_DELETE_POLICY",
                to_value(p)?,
            ),
            Self::DeletePolicies(p) => (
                "policy.delete",
                "delete_policies",
                "ACTIVITY_TYPE_DELETE_POLICIES",
                to_value(p)?,
            ),
            Self::RegisterKeys(p) => (
                "api-key.register",
                "create_api_keys",
                "ACTIVITY_TYPE_CREATE_API_KEYS_V2",
                to_value(p)?,
            ),
            Self::DeleteKeys(p) => (
                "api-key.delete",
                "delete_api_keys",
                "ACTIVITY_TYPE_DELETE_API_KEYS",
                to_value(p)?,
            ),
        };
        submit_activity(&auth, command, endpoint, kind, &params).await
    }
}

fn resolve_tag_name(tags: &[Tag], name: String) -> Result<&str> {
    let matches: Vec<&str> = tags
        .iter()
        .filter(|tag| tag.tag_name == name)
        .map(|tag| tag.tag_id.as_str())
        .collect();
    match matches.as_slice() {
        [] => Err(MissingResource::new("user tag", name).into()),
        [one] => Ok(one),
        many => Err(InvalidInput(format!(
            "{} tags are named {name}; pass --tag with one of: {}",
            many.len(),
            many.join(", ")
        ))
        .into()),
    }
}

impl Query {
    async fn run(self, auth: ResolvedAuth) -> Result<OperationOutput> {
        let organization_id = auth.org_id.to_string();
        let client = build_turnkey_client(auth.stamper, &auth.api_base_url)?;
        let (command, data) = match self {
            Self::Users { tag } => {
                let tag_id = match tag {
                    Some(selector) => {
                        let listed = client
                            .list_user_tags(query::ListUserTagsRequest {
                                organization_id: organization_id.clone(),
                            })
                            .await?;
                        Some(match selector {
                            TagSelector::Name(name) => {
                                resolve_tag_name(&listed.user_tags, name)?.to_owned()
                            }
                            TagSelector::Id(id) => {
                                let id = id.to_string();
                                if !listed.user_tags.iter().any(|tag| tag.tag_id == id) {
                                    return Err(MissingResource::new("user tag", id).into());
                                }
                                id
                            }
                        })
                    }
                    None => None,
                };
                let query::GetUsersResponse { mut users } = client
                    .get_users(query::GetUsersRequest { organization_id })
                    .await?;
                if let Some(tag_id) = &tag_id {
                    users.retain(|user| user.user_tags.contains(tag_id));
                }
                ("user.list", to_value(query::GetUsersResponse { users })?)
            }
            Self::User(id) => {
                let response = client
                    .get_user(query::GetUserRequest {
                        organization_id,
                        user_id: id.to_string(),
                    })
                    .await?;
                if response.user.is_none() {
                    return Err(MissingResource::new("user", id.to_string()).into());
                }
                ("user.get", to_value(response)?)
            }
            Self::Tags => (
                "user.tag.list",
                to_value(
                    client
                        .list_user_tags(query::ListUserTagsRequest { organization_id })
                        .await?,
                )?,
            ),
            Self::Policies => (
                "policy.list",
                to_value(
                    client
                        .get_policies(query::GetPoliciesRequest { organization_id })
                        .await?,
                )?,
            ),
            Self::Policy(id) => {
                let response = client
                    .get_policy(query::GetPolicyRequest {
                        organization_id,
                        policy_id: id.to_string(),
                    })
                    .await?;
                if response.policy.is_none() {
                    return Err(MissingResource::new("policy", id.to_string()).into());
                }
                ("policy.get", to_value(response)?)
            }
            Self::Evaluations(id) => (
                "policy.evaluations",
                to_value(
                    client
                        .get_policy_evaluations(query::GetPolicyEvaluationsRequest {
                            organization_id,
                            activity_id: id.to_string(),
                        })
                        .await?,
                )?,
            ),
            Self::ApiKeys { owner, expiry } => {
                let owned: Vec<(String, Vec<ApiKey>)> = match owner {
                    KeyOwner::User(user_id) => {
                        let user_id = user_id.to_string();
                        let query::GetApiKeysResponse { api_keys } = client
                            .get_api_keys(query::GetApiKeysRequest {
                                organization_id,
                                user_id: Some(user_id.clone()),
                            })
                            .await?;
                        vec![(user_id, api_keys)]
                    }
                    KeyOwner::AllUsers => {
                        let query::GetUsersResponse { users } = client
                            .get_users(query::GetUsersRequest { organization_id })
                            .await?;
                        users
                            .into_iter()
                            .map(|user| (user.user_id, user.api_keys))
                            .collect()
                    }
                };
                let mut keys = Vec::new();
                for (user_id, api_keys) in owned {
                    for key in api_keys {
                        let expires_at = expires_at_unix_ms(&key)?;
                        let keep = match expiry {
                            None => true,
                            Some(ExpiryFilter::ExpiresBy(deadline)) => {
                                expires_at.is_some_and(|at| at <= deadline)
                            }
                            Some(ExpiryFilter::LongLived) => expires_at.is_none(),
                        };
                        if !keep {
                            continue;
                        }
                        let mut key = to_value(key)?;
                        key["expiresAt"] = expires_at.map(|ms| ms.to_string()).into();
                        key["userId"] = user_id.as_str().into();
                        keys.push(key);
                    }
                }
                (
                    "api-key.list",
                    Value::Object(Map::from_iter([("apiKeys".to_owned(), Value::Array(keys))])),
                )
            }
        };
        Ok(OperationOutput::result(command, data))
    }
}

// Asserts on the classified error code.
#[cfg(test)]
#[allow(clippy::disallowed_types)]
mod tests {
    use std::iter::once;

    use clap::Parser;
    use serde_json::{from_value, json, to_vec};
    use tempfile::NamedTempFile;
    use turnkey_client::generated::external::{activity::v1 as activity, data::v1::Timestamp};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;
    use crate::errors::{Classification, ErrorCode, classify};

    const ID: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER: &str = "22222222-2222-4222-8222-222222222222";

    fn auth(server: &MockServer) -> ResolvedAuth {
        ResolvedAuth::for_tests(ID, &server.uri(), TurnkeyP256ApiKey::generate())
    }

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: TestCommand,
    }

    #[derive(Subcommand)]
    enum TestCommand {
        User {
            #[command(subcommand)]
            command: UserCommand,
        },
        Policy {
            #[command(subcommand)]
            command: PolicyCommand,
        },
        ApiKey {
            #[command(subcommand)]
            command: ApiKeyCommand,
        },
    }

    fn prepare(args: &[&str]) -> Result<PreparedResource> {
        let cli = TestCli::try_parse_from(once("tk").chain(args.iter().copied()))?;
        match cli.command {
            TestCommand::User { command } => command.prepare(),
            TestCommand::Policy { command } => command.prepare(),
            TestCommand::ApiKey { command } => command.prepare(),
        }
    }

    #[test]
    fn malformed_and_unsupported_inputs_fail_before_auth() {
        for args in [
            vec!["user", "get", "--id", "not-a-uuid"],
            vec!["user", "delete"],
            vec!["policy", "delete"],
            vec!["policy", "list", "--cursor", "invented"],
            vec!["api-key", "list", "--all-users", "--expiring-within", "2w"],
            vec!["api-key", "list"],
            vec!["api-key", "list", "--user-id", "not-a-uuid"],
            vec![
                "api-key",
                "list",
                "--user-id",
                "8d4b1e7a-0c6d-4d1a-9d3e-6b0f1c2d3e4f",
                "--all-users",
            ],
            vec![
                "api-key",
                "list",
                "--all-users",
                "--expired",
                "--long-lived",
            ],
            vec![
                "api-key",
                "list",
                "--all-users",
                "--expiring-within",
                "2h",
                "--expired",
            ],
            vec![
                "policy",
                "create",
                "--input-json",
                "{}",
                "--input-file",
                "-",
            ],
            vec!["policy", "create"],
            vec!["policy", "create", "--name", "p", "--condition", "true"],
            vec!["policy", "create", "--name", "p", "--effect", "allow"],
            vec![
                "policy",
                "create",
                "--effect",
                "allow",
                "--input-json",
                "{}",
            ],
            vec!["user", "create", "--input-json", r#"{"users":[]}"#],
            vec![
                "api-key",
                "register",
                "--input-json",
                r#"{"userId":"bad","apiKeys":[]}"#,
            ],
            vec![
                "policy",
                "update",
                "--input-json",
                r#"{"policyId":"11111111-1111-4111-8111-111111111111","effect":"EFFECT_ALLOW"}"#,
            ],
            vec![
                "user",
                "create",
                "--input-json",
                r#"{"users":[{"userName":"agent","apiKeys":[{"apiKeyName":"key","publicKey":"03ab","curveType":"API_KEY_CURVE_P256","privateKey":"secret"}]}]}"#,
            ],
        ] {
            assert!(
                prepare(&args).is_err(),
                "input unexpectedly accepted: {args:?}"
            );
        }
    }

    #[test]
    fn policy_file_preserves_exact_expressions() {
        let file = NamedTempFile::new().unwrap();
        let params = json!({
            "policyName": "agent policy",
            "effect": "EFFECT_ALLOW",
            "condition": "activity.action == 'SIGN' &&\n  wallet.id == 'literal'",
            "consensus": "approvers.any(user, user.id == 'literal')",
            "notes": "Reviewed policy",
            "time": null
        });
        fs::write(file.path(), to_vec(&params).unwrap()).unwrap();
        let body = file.path().display().to_string();
        let command = prepare(&["policy", "create", "--input-file", &body]).unwrap();
        let PreparedResource::Mutation(Mutation::CreatePolicy(actual)) = command else {
            panic!("expected prepared policy creation")
        };
        assert_eq!(to_value(actual).unwrap(), params);
    }

    #[tokio::test]
    async fn all_mutations_use_versioned_envelopes_and_submit_once() {
        let user_body = r#"{"users":[{"userName":"agent","userTags":["11111111-1111-4111-8111-111111111111"]}]}"#;
        let update_user =
            r#"{"userId":"11111111-1111-4111-8111-111111111111","userName":"renamed"}"#;
        let tag_body =
            r#"{"userTagName":"agents","userIds":["11111111-1111-4111-8111-111111111111"]}"#;
        let update_tag = r#"{"userTagId":"11111111-1111-4111-8111-111111111111","addUserIds":["22222222-2222-4222-8222-222222222222"]}"#;
        let policy_body = r#"{"policyName":"agent","effect":"EFFECT_ALLOW","condition":"true","consensus":"true","notes":"test"}"#;
        let policies_body =
            r#"{"policies":[{"policyName":"agent","effect":"EFFECT_ALLOW","notes":"test"}]}"#;
        let update_policy = r#"{"policyId":"11111111-1111-4111-8111-111111111111","policyEffect":"EFFECT_DENY","policyCondition":"true"}"#;
        let keys_body = r#"{"userId":"11111111-1111-4111-8111-111111111111","apiKeys":[{"apiKeyName":"agent","publicKey":"03ab","curveType":"API_KEY_CURVE_P256"}]}"#;
        let cases = [
            (
                vec!["user", "create", "--input-json", user_body],
                "create_users",
                "ACTIVITY_TYPE_CREATE_USERS_V4",
            ),
            (
                vec!["user", "update", "--input-json", update_user],
                "update_user",
                "ACTIVITY_TYPE_UPDATE_USER",
            ),
            (
                vec!["user", "delete", "--id", ID],
                "delete_users",
                "ACTIVITY_TYPE_DELETE_USERS",
            ),
            (
                vec!["user", "tag", "create", "--input-json", tag_body],
                "create_user_tag",
                "ACTIVITY_TYPE_CREATE_USER_TAG",
            ),
            (
                vec!["user", "tag", "update", "--input-json", update_tag],
                "update_user_tag",
                "ACTIVITY_TYPE_UPDATE_USER_TAG",
            ),
            (
                vec!["user", "tag", "delete", "--id", ID],
                "delete_user_tags",
                "ACTIVITY_TYPE_DELETE_USER_TAGS",
            ),
            (
                vec!["policy", "create", "--input-json", policy_body],
                "create_policy",
                "ACTIVITY_TYPE_CREATE_POLICY_V3",
            ),
            (
                vec!["policy", "create-batch", "--input-json", policies_body],
                "create_policies",
                "ACTIVITY_TYPE_CREATE_POLICIES",
            ),
            (
                vec!["policy", "update", "--input-json", update_policy],
                "update_policy",
                "ACTIVITY_TYPE_UPDATE_POLICY_V2",
            ),
            (
                vec!["policy", "delete", "--id", ID],
                "delete_policy",
                "ACTIVITY_TYPE_DELETE_POLICY",
            ),
            (
                vec!["policy", "delete", "--id", ID, "--id", OTHER],
                "delete_policies",
                "ACTIVITY_TYPE_DELETE_POLICIES",
            ),
            (
                vec!["api-key", "register", "--input-json", keys_body],
                "create_api_keys",
                "ACTIVITY_TYPE_CREATE_API_KEYS_V2",
            ),
            (
                vec!["api-key", "delete", "--user-id", ID, "--id", OTHER],
                "delete_api_keys",
                "ACTIVITY_TYPE_DELETE_API_KEYS",
            ),
        ];
        for (args, endpoint, kind) in cases {
            for status in [
                "ACTIVITY_STATUS_PENDING",
                "ACTIVITY_STATUS_CONSENSUS_NEEDED",
                "ACTIVITY_STATUS_REJECTED",
                "ACTIVITY_STATUS_FAILED",
                "ACTIVITY_STATUS_COMPLETED",
            ] {
                let server = MockServer::start().await;
                let expected: activity::Activity = from_value(json!({
                    "id": OTHER, "organizationId": ID, "type": kind,
                    "status": status, "fingerprint": "fixture"
                }))
                .unwrap();
                Mock::given(method("POST"))
                    .and(path(format!("/public/v1/submit/{endpoint}")))
                    .respond_with(
                        ResponseTemplate::new(200).set_body_json(json!({"activity": expected})),
                    )
                    .expect(1)
                    .mount(&server)
                    .await;
                let result = prepare(&args).unwrap().run(auth(&server)).await;
                match result {
                    Ok(output) => {
                        assert!(!matches!(
                            status,
                            "ACTIVITY_STATUS_REJECTED" | "ACTIVITY_STATUS_FAILED"
                        ));
                        assert_eq!(
                            to_value(output).unwrap()["data"]["activity"],
                            to_value(expected).unwrap()
                        );
                    }
                    Err(error) => {
                        assert!(matches!(
                            status,
                            "ACTIVITY_STATUS_REJECTED" | "ACTIVITY_STATUS_FAILED"
                        ));
                        let failure = error.downcast_ref::<ActivityError>().unwrap();
                        assert_eq!(failure.kind(), ActivityErrorKind::NotCompleted);
                        assert_eq!(
                            failure.activity(),
                            Some(&json!({"id": OTHER, "status": status}))
                        );
                    }
                }
                let requests = server.received_requests().await.unwrap();
                assert_eq!(requests.len(), 1);
                let body: Value = from_slice(&requests[0].body).unwrap();
                assert_eq!(body["type"], kind);
                assert_eq!(body["organizationId"], ID);
                assert!(
                    body["timestampMs"]
                        .as_str()
                        .unwrap()
                        .parse::<u128>()
                        .unwrap()
                        > 0
                );
                assert!(requests[0].headers.contains_key("x-stamp"));
                if endpoint == "update_policy" {
                    assert_eq!(
                        body["parameters"],
                        json!({
                            "policyId": ID, "policyName": null, "policyEffect": "EFFECT_DENY",
                            "policyCondition": "true", "policyConsensus": null,
                            "policyNotes": null, "time": null
                        })
                    );
                }
                server.verify().await;
            }
        }
    }

    #[test]
    fn listed_key_expiry_distinguishes_absent_from_malformed() {
        let key = |created_at: Option<&str>, expiration_seconds: Option<u64>| ApiKey {
            credential: None,
            api_key_id: ID.to_owned(),
            api_key_name: "key".to_owned(),
            created_at: created_at.map(|seconds| Timestamp {
                seconds: seconds.to_owned(),
                nanos: "0".to_owned(),
            }),
            updated_at: None,
            expiration_seconds,
        };
        assert_eq!(
            expires_at_unix_ms(&key(Some("1700000000"), None)).unwrap(),
            None
        );
        assert_eq!(
            expires_at_unix_ms(&key(Some("1700000000"), Some(7200))).unwrap(),
            Some(1_700_007_200_000)
        );
        let error = expires_at_unix_ms(&key(Some("soon"), Some(7200))).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<Malformed>()
                .expect("a Malformed error")
                .to_string(),
            r#"get_api_keys returned a non-numeric apiKeys[].createdAt.seconds: "soon""#
        );
        let error = expires_at_unix_ms(&key(None, Some(7200))).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<ActivityError>()
                .expect("an ActivityError")
                .to_string(),
            "get_api_keys returned an expiring apiKeys[] entry without createdAt"
        );
    }

    #[tokio::test]
    async fn missing_lookup_preserves_typed_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/public/v1/query/get_user"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"user": null})))
            .mount(&server)
            .await;
        let result = prepare(&["user", "get", "--id", ID])
            .unwrap()
            .run(auth(&server))
            .await;
        let error = result.unwrap_err();
        assert_eq!(error.to_string(), format!("user not found: {ID}"));
        assert_eq!(
            classify(&error),
            Classification {
                code: ErrorCode::NotFound,
                http_status: None,
            }
        );
    }
    #[tokio::test]
    async fn mutation_transport_refuses_redirects_and_preserves_uncertain_outcomes() {
        for (template, expected) in [
            (
                ResponseTemplate::new(307).insert_header("Location", "/redirect-target"),
                Classification {
                    code: ErrorCode::ApiError,
                    http_status: Some(307),
                },
            ),
            (
                ResponseTemplate::new(308).insert_header("Location", "/redirect-target"),
                Classification {
                    code: ErrorCode::ApiError,
                    http_status: Some(308),
                },
            ),
            (
                ResponseTemplate::new(200).set_body_string("not JSON"),
                Classification {
                    code: ErrorCode::SubmissionUnknown,
                    http_status: None,
                },
            ),
            (
                ResponseTemplate::new(200).set_body_json(json!({})),
                Classification {
                    code: ErrorCode::SubmissionUnknown,
                    http_status: None,
                },
            ),
            (
                ResponseTemplate::new(401).set_body_json(json!({"message":"denied"})),
                Classification {
                    code: ErrorCode::Unauthorized,
                    http_status: Some(401),
                },
            ),
            (
                ResponseTemplate::new(403).set_body_json(json!({"message":"denied"})),
                Classification {
                    code: ErrorCode::Unauthorized,
                    http_status: Some(403),
                },
            ),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/public/v1/submit/delete_users"))
                .respond_with(template)
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(path("/redirect-target"))
                .respond_with(ResponseTemplate::new(200))
                .expect(0)
                .mount(&server)
                .await;
            let error = prepare(&["user", "delete", "--id", ID])
                .unwrap()
                .run(auth(&server))
                .await
                .unwrap_err();
            assert_eq!(classify(&error), expected);
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
            server.verify().await;
        }
    }
}
