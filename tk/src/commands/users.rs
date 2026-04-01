use anyhow::{Result, anyhow};
use clap::{Args as ClapArgs, Subcommand, ValueEnum};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::generated::immutable::activity::v1 as activity;
use turnkey_client::generated::immutable::common::v1::ApiKeyCurve;

#[derive(Debug, ClapArgs)]
#[command(about = "User management commands.")]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

pub async fn run(args: Args) -> Result<()> {
    match args.command {
        Command::Create(args) => create(args).await,
        Command::Delete(args) => delete(args).await,
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new user.
    Create(CreateArgs),
    /// Delete one or more users.
    Delete(DeleteArgs),
}

#[derive(Debug, ClapArgs)]
struct CreateArgs {
    /// Human-readable name for the user.
    #[arg(long)]
    name: String,
    /// Email address for the user.
    #[arg(long)]
    email: Option<String>,
    /// Phone number in E.164 format.
    #[arg(long)]
    phone: Option<String>,
    /// User tag IDs to associate.
    #[arg(long = "tag")]
    tags: Vec<String>,
    /// Name for an API key to create with the user.
    #[arg(long)]
    api_key_name: Option<String>,
    /// Hex-encoded public key for the API key. If omitted and --api-key-name is set, a P256 key pair is generated automatically.
    #[arg(long)]
    api_key_public_key: Option<String>,
    /// Curve for the API key.
    #[arg(long, default_value = "p256")]
    api_key_curve: ApiKeyCurveArg,
    /// Expiration for the API key in seconds.
    #[arg(long)]
    api_key_expiration_seconds: Option<String>,
}

#[derive(Debug, ClapArgs)]
struct DeleteArgs {
    /// User IDs to delete.
    #[arg(long = "user-id", required = true)]
    user_ids: Vec<String>,
}

#[derive(Debug, Clone, ValueEnum)]
enum ApiKeyCurveArg {
    P256,
    Secp256k1,
    Ed25519,
}

impl From<ApiKeyCurveArg> for ApiKeyCurve {
    fn from(c: ApiKeyCurveArg) -> Self {
        match c {
            ApiKeyCurveArg::P256 => ApiKeyCurve::P256,
            ApiKeyCurveArg::Secp256k1 => ApiKeyCurve::Secp256k1,
            ApiKeyCurveArg::Ed25519 => ApiKeyCurve::Ed25519,
        }
    }
}

async fn create(args: CreateArgs) -> Result<()> {
    let config = turnkey_auth::config::Config::resolve().await?;
    let signer = turnkey_auth::turnkey::TurnkeySigner::new(config)?;
    let client = signer.client();
    let org_id = signer.organization_id().to_string();

    let mut api_keys = Vec::new();
    let mut api_public_key: Option<String> = None;
    let mut api_private_key: Option<String> = None;

    if let Some(api_key_name) = &args.api_key_name {
        let (public_key_hex, curve): (String, ApiKeyCurve) = match &args.api_key_public_key {
            Some(pk) => (pk.clone(), args.api_key_curve.into()),
            None => {
                let key = TurnkeyP256ApiKey::generate();
                api_private_key = Some(hex::encode(key.private_key()));
                (hex::encode(key.compressed_public_key()), ApiKeyCurve::P256)
            }
        };

        api_public_key = Some(public_key_hex.clone());
        api_keys.push(activity::ApiKeyParamsV2 {
            api_key_name: api_key_name.clone(),
            public_key: public_key_hex,
            curve_type: curve.into(),
            expiration_seconds: args.api_key_expiration_seconds,
        });
    }

    let response = client
        .create_users(
            org_id,
            client.current_timestamp(),
            activity::CreateUsersIntentV4 {
                users: vec![activity::UserParamsV4 {
                    user_name: args.name,
                    user_email: args.email,
                    user_phone_number: args.phone,
                    api_keys,
                    authenticators: Vec::new(),
                    oauth_providers: Vec::new(),
                    user_tags: args.tags,
                }],
            },
        )
        .await
        .map_err(|e| anyhow!("failed to create user: {e}"))?;

    let user_id = response
        .result
        .user_ids
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("Turnkey did not return the created user ID"))?;

    let mut output = serde_json::json!({ "userId": user_id });

    if let Some(pk) = api_public_key {
        output["apiPublicKey"] = serde_json::Value::String(pk);
    }
    if let Some(sk) = api_private_key {
        output["apiPrivateKey"] = serde_json::Value::String(sk);
    }

    println!("{output}");
    Ok(())
}

async fn delete(args: DeleteArgs) -> Result<()> {
    let config = turnkey_auth::config::Config::resolve().await?;
    let signer = turnkey_auth::turnkey::TurnkeySigner::new(config)?;
    let client = signer.client();
    let org_id = signer.organization_id().to_string();

    client
        .delete_users(
            org_id,
            client.current_timestamp(),
            activity::DeleteUsersIntent {
                user_ids: args.user_ids.clone(),
            },
        )
        .await
        .map_err(|e| anyhow!("failed to delete users: {e}"))?;

    println!("{}", serde_json::json!({ "deletedUserIds": args.user_ids }));
    Ok(())
}
