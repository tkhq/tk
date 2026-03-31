use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_auth::config::Config;
use turnkey_auth::ssh::{
    DEFAULT_HASH_ALGORITHM, build_signed_data, encode_armored_signature, encode_public_key_line,
};
use turnkey_auth::turnkey::TurnkeySigner;
use turnkey_client::generated::immutable::activity::v1 as immutable_activity;
use turnkey_client::generated::immutable::common::v1::{AddressFormat, ApiKeyCurve, Curve, Effect};
use turnkey_client::{TurnkeyClient, TurnkeyClientError};

#[derive(Debug, Parser)]
#[command(
    about = "Consensus signing demo utilities for local Turnkey stacks.",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create demo resources and write agent artifacts.
    Setup(SetupArgs),
    /// Attempt a Git-signing request with the demo agent credentials.
    Sign(SignArgs),
    /// Remove demo resources created during setup.
    Teardown(TeardownArgs),
}

#[derive(Debug, Args)]
struct SetupArgs {
    /// Turnkey organization ID for the local demo org.
    #[arg(long)]
    org_id: String,
    /// Local Turnkey API URL.
    #[arg(long, default_value = "http://localhost:8081")]
    api_url: String,
    /// JSON credentials file exported from the local dashboard.
    #[arg(long)]
    credentials: Option<PathBuf>,
    /// Directory used for the generated state and helper files.
    #[arg(long, default_value = "target/consensus-demo")]
    output_dir: PathBuf,
}

#[derive(Debug, Args)]
struct SignArgs {
    /// Payload to sign through the demo agent credentials.
    #[arg(long, default_value = "hello world")]
    payload: String,
    /// Directory containing the generated setup state.
    #[arg(long, default_value = "target/consensus-demo")]
    output_dir: PathBuf,
}

#[derive(Debug, Args)]
struct TeardownArgs {
    /// JSON credentials file exported from the local dashboard.
    #[arg(long)]
    credentials: Option<PathBuf>,
    /// Directory containing the generated setup state.
    #[arg(long, default_value = "target/consensus-demo")]
    output_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DemoState {
    organization_id: String,
    api_url: String,
    private_key_id: String,
    agent_user_id: String,
    tag_id: String,
    policy_id: String,
    agent_api_public_key: String,
    agent_api_private_key: String,
}

#[derive(Debug, Clone, Deserialize)]
struct CredentialFileEntry {
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "privateKey")]
    private_key: String,
}

#[derive(Debug, Clone)]
struct RootCredentials {
    public_key: String,
    private_key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Setup(args) => setup(args).await,
        Command::Sign(args) => sign(args).await,
        Command::Teardown(args) => teardown(args).await,
    }
}

async fn setup(args: SetupArgs) -> Result<()> {
    let root_credentials = load_root_credentials(args.credentials.as_deref())?;
    let client = build_client(&root_credentials, &args.api_url)?;
    let suffix = format!("{:x}", client.current_timestamp());

    let private_key = client
        .create_private_keys(
            args.org_id.clone(),
            client.current_timestamp(),
            immutable_activity::CreatePrivateKeysIntentV2 {
                private_keys: vec![immutable_activity::PrivateKeyParams {
                    private_key_name: format!("demo-signer-{suffix}-key"),
                    curve: Curve::Ed25519.into(),
                    private_key_tags: Vec::new(),
                    address_formats: vec![AddressFormat::Solana.into()],
                }],
            },
        )
        .await
        .map_err(map_turnkey_error)?
        .result
        .private_keys
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("Turnkey did not return the created private key"))?;

    let agent_key = TurnkeyP256ApiKey::generate();
    let agent_public_key = hex::encode(agent_key.compressed_public_key());
    let agent_private_key = hex::encode(agent_key.private_key());

    let user = client
        .create_users(
            args.org_id.clone(),
            client.current_timestamp(),
            immutable_activity::CreateUsersIntentV4 {
                users: vec![immutable_activity::UserParamsV4 {
                    user_name: format!("demo-agent-{suffix}"),
                    user_email: Some(format!("agent-{suffix}@demo.local")),
                    user_phone_number: None,
                    api_keys: vec![immutable_activity::ApiKeyParamsV2 {
                        api_key_name: format!("agent-key-{suffix}"),
                        public_key: agent_public_key.clone(),
                        curve_type: ApiKeyCurve::P256.into(),
                        expiration_seconds: None,
                    }],
                    authenticators: Vec::new(),
                    oauth_providers: Vec::new(),
                    user_tags: Vec::new(),
                }],
            },
        )
        .await
        .map_err(map_turnkey_error)?
        .result
        .user_ids
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("Turnkey did not return the created user ID"))?;

    let tag = client
        .create_user_tag(
            args.org_id.clone(),
            client.current_timestamp(),
            immutable_activity::CreateUserTagIntent {
                user_tag_name: format!("demo-signer-{suffix}"),
                user_ids: vec![user.clone()],
            },
        )
        .await
        .map_err(map_turnkey_error)?
        .result;

    let policy = client
        .create_policy(
            args.org_id.clone(),
            client.current_timestamp(),
            immutable_activity::CreatePolicyIntentV3 {
                policy_name: format!("demo-consensus-signing-{suffix}"),
                effect: Effect::Allow.into(),
                condition: Some(format!(
                    "private_key.id == '{}' && activity.action == 'SIGN'",
                    private_key.private_key_id
                )),
                consensus: Some("approvers.count() >= 2".to_string()),
                notes: "Requires a second approver for signing with the demo Ed25519 key"
                    .to_string(),
            },
        )
        .await
        .map_err(map_turnkey_error)?
        .result;

    let state = DemoState {
        organization_id: args.org_id,
        api_url: args.api_url,
        private_key_id: private_key.private_key_id,
        agent_user_id: user,
        tag_id: tag.user_tag_id,
        policy_id: policy.policy_id,
        agent_api_public_key: agent_public_key,
        agent_api_private_key: agent_private_key,
    };

    tokio::fs::create_dir_all(&args.output_dir)
        .await
        .with_context(|| format!("failed to create {}", args.output_dir.display()))?;
    write_state(&args.output_dir, &state).await?;
    write_agent_env(&args.output_dir, &state).await?;

    println!("Setup complete.");
    println!("Artifacts: {}", args.output_dir.display());
    println!("  State file: {}", state_path(&args.output_dir).display());
    println!(
        "  Agent env:  {}",
        agent_env_path(&args.output_dir).display()
    );
    println!("Next steps:");
    println!(
        "  cargo run -p tk --example consensus_demo -- sign --output-dir {}",
        args.output_dir.display()
    );
    println!("  source {}", agent_env_path(&args.output_dir).display());
    println!(
        "  cargo run -p tk -- ssh public-key > {}/demo-key.pub",
        args.output_dir.display()
    );
    println!(
        "  cargo run -p tk -- ssh git-sign -Y sign -n git -f {}/demo-key.pub {}/demo-payload.txt",
        args.output_dir.display(),
        args.output_dir.display()
    );
    println!("Approve the pending activity in the dashboard after the sign attempt.");
    Ok(())
}

async fn sign(args: SignArgs) -> Result<()> {
    let state = read_state(&args.output_dir).await?;
    tokio::fs::create_dir_all(&args.output_dir)
        .await
        .with_context(|| format!("failed to create {}", args.output_dir.display()))?;

    let signer = TurnkeySigner::new(Config {
        organization_id: state.organization_id.clone(),
        api_public_key: state.agent_api_public_key.clone(),
        api_private_key: state.agent_api_private_key.clone(),
        private_key_id: state.private_key_id.clone(),
        api_base_url: state.api_url.clone(),
    })?;

    let public_key = signer.get_public_key().await?;
    let public_key_line = encode_public_key_line(&public_key, Some("consensus-demo"))?;
    let public_key_blob =
        turnkey_auth::ssh::parse_public_key_line(&public_key_line)?.public_key_blob;
    let payload_path = args.output_dir.join("demo-payload.txt");
    let public_key_path = args.output_dir.join("demo-key.pub");
    let signature_path = args.output_dir.join("demo-payload.txt.sig");
    let payload = args.payload.into_bytes();

    tokio::fs::write(&payload_path, &payload)
        .await
        .with_context(|| format!("failed to write {}", payload_path.display()))?;
    tokio::fs::write(&public_key_path, format!("{public_key_line}\n"))
        .await
        .with_context(|| format!("failed to write {}", public_key_path.display()))?;

    let signed_data = build_signed_data("git", &payload);
    match signer.sign_ed25519(&signed_data).await {
        Ok(signature) => {
            let armored = encode_armored_signature(
                &public_key_blob,
                "git",
                DEFAULT_HASH_ALGORITHM,
                &signature,
            )?;
            tokio::fs::write(&signature_path, armored)
                .await
                .with_context(|| format!("failed to write {}", signature_path.display()))?;
            println!("Signing succeeded unexpectedly.");
            println!("  Signature: {}", signature_path.display());
        }
        Err(error) => {
            println!("{error}");
            println!("The sign attempt should now be pending in the dashboard.");
        }
    }

    println!("Artifacts:");
    println!("  Payload:    {}", payload_path.display());
    println!("  Public key: {}", public_key_path.display());
    println!("CLI reproduction:");
    println!("  source {}", agent_env_path(&args.output_dir).display());
    println!(
        "  cargo run -p tk -- ssh git-sign -Y sign -n git -f {} {}",
        public_key_path.display(),
        payload_path.display()
    );
    Ok(())
}

async fn teardown(args: TeardownArgs) -> Result<()> {
    let state = read_state(&args.output_dir).await?;
    let root_credentials = load_root_credentials(args.credentials.as_deref())?;
    let client = build_client(&root_credentials, &state.api_url)?;

    client
        .delete_policy(
            state.organization_id.clone(),
            client.current_timestamp(),
            immutable_activity::DeletePolicyIntent {
                policy_id: state.policy_id.clone(),
            },
        )
        .await
        .map_err(map_turnkey_error)?;
    client
        .delete_user_tags(
            state.organization_id.clone(),
            client.current_timestamp(),
            immutable_activity::DeleteUserTagsIntent {
                user_tag_ids: vec![state.tag_id.clone()],
            },
        )
        .await
        .map_err(map_turnkey_error)?;
    client
        .delete_users(
            state.organization_id.clone(),
            client.current_timestamp(),
            immutable_activity::DeleteUsersIntent {
                user_ids: vec![state.agent_user_id.clone()],
            },
        )
        .await
        .map_err(map_turnkey_error)?;
    client
        .delete_private_keys(
            state.organization_id.clone(),
            client.current_timestamp(),
            immutable_activity::DeletePrivateKeysIntent {
                private_key_ids: vec![state.private_key_id.clone()],
                delete_without_export: Some(true),
            },
        )
        .await
        .map_err(map_turnkey_error)?;

    if tokio::fs::try_exists(&args.output_dir).await? {
        tokio::fs::remove_dir_all(&args.output_dir)
            .await
            .with_context(|| format!("failed to remove {}", args.output_dir.display()))?;
    }

    println!("Teardown complete.");
    Ok(())
}

fn load_root_credentials(path: Option<&Path>) -> Result<RootCredentials> {
    if let Some(path) = path {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let mut entries: Vec<CredentialFileEntry> =
            serde_json::from_str(&contents).context("failed to parse credentials JSON")?;
        let first = entries
            .drain(..)
            .next()
            .ok_or_else(|| anyhow!("credentials file did not contain any entries"))?;
        return Ok(RootCredentials {
            public_key: first.public_key,
            private_key: first.private_key,
        });
    }

    let public_key = std::env::var("TURNKEY_API_PUBLIC_KEY")
        .context("missing TURNKEY_API_PUBLIC_KEY and no --credentials file was provided")?;
    let private_key = std::env::var("TURNKEY_API_PRIVATE_KEY")
        .context("missing TURNKEY_API_PRIVATE_KEY and no --credentials file was provided")?;

    Ok(RootCredentials {
        public_key,
        private_key,
    })
}

fn build_client(
    credentials: &RootCredentials,
    api_url: &str,
) -> Result<TurnkeyClient<TurnkeyP256ApiKey>> {
    let api_key =
        TurnkeyP256ApiKey::from_strings(&credentials.private_key, Some(&credentials.public_key))
            .context("failed to parse Turnkey API key")?;

    TurnkeyClient::builder()
        .api_key(api_key)
        .base_url(api_url)
        .build()
        .context("failed to build Turnkey client")
}

fn map_turnkey_error(error: TurnkeyClientError) -> anyhow::Error {
    anyhow!("Turnkey API request failed: {error}")
}

async fn write_state(output_dir: &Path, state: &DemoState) -> Result<()> {
    let rendered = serde_json::to_vec_pretty(state).context("failed to serialize state")?;
    let path = state_path(output_dir);
    tokio::fs::write(&path, rendered)
        .await
        .with_context(|| format!("failed to write {}", path.display()))
}

async fn read_state(output_dir: &Path) -> Result<DemoState> {
    let path = state_path(output_dir);
    let contents = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&contents).context("failed to parse demo state")
}

async fn write_agent_env(output_dir: &Path, state: &DemoState) -> Result<()> {
    let contents = format!(
        "export TURNKEY_ORGANIZATION_ID=\"{}\"\n\
export TURNKEY_API_PUBLIC_KEY=\"{}\"\n\
export TURNKEY_API_PRIVATE_KEY=\"{}\"\n\
export TURNKEY_PRIVATE_KEY_ID=\"{}\"\n\
export TURNKEY_API_BASE_URL=\"{}\"\n",
        state.organization_id,
        state.agent_api_public_key,
        state.agent_api_private_key,
        state.private_key_id,
        state.api_url,
    );
    let path = agent_env_path(output_dir);
    tokio::fs::write(&path, contents)
        .await
        .with_context(|| format!("failed to write {}", path.display()))
}

fn state_path(output_dir: &Path) -> PathBuf {
    output_dir.join("state.json")
}

fn agent_env_path(output_dir: &Path) -> PathBuf {
    output_dir.join("agent.env")
}
