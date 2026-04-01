use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::generated::immutable::activity::v1 as activity;
use turnkey_client::generated::immutable::common::v1::{
    AddressFormat, ApiKeyCurve, Curve, Effect, HashFunction, PayloadEncoding,
};
use turnkey_client::generated::{GetActivityRequest, SignRawPayloadIntentV2};
use turnkey_client::{TurnkeyClient, TurnkeyClientError};

#[derive(Debug, Parser)]
#[command(about = "Consensus signing demo for local Turnkey stacks.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create demo resources (private key, user, tag, policy) and write artifacts.
    Setup {
        /// Directory for generated state and helper files.
        #[arg(long, default_value = "target/consensus-demo")]
        output_dir: PathBuf,
    },
    /// Attempt a raw-payload signing request with the demo agent credentials.
    Sign {
        /// Plain-text payload to sign.
        #[arg(long, default_value = "hello world")]
        payload: String,
        /// Directory containing the generated setup state.
        #[arg(long, default_value = "target/consensus-demo")]
        output_dir: PathBuf,
    },
    /// Remove demo resources created during setup.
    Teardown {
        /// Directory containing the generated setup state.
        #[arg(long, default_value = "target/consensus-demo")]
        output_dir: PathBuf,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DemoState {
    organization_id: String,
    api_url: String,
    private_key_id: String,
    agent_user_id: String,
    policy_id: String,
    agent_api_public_key: String,
    agent_api_private_key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Setup { output_dir } => setup(output_dir).await,
        Command::Sign { payload, output_dir } => sign(payload, output_dir).await,
        Command::Teardown { output_dir } => teardown(output_dir).await,
    }
}

// Credential helpers following the rust-sdk/examples pattern.

fn load_api_key_from_env() -> Result<TurnkeyP256ApiKey> {
    let public_key =
        env::var("TURNKEY_API_PUBLIC_KEY").context("missing TURNKEY_API_PUBLIC_KEY")?;
    let private_key =
        env::var("TURNKEY_API_PRIVATE_KEY").context("missing TURNKEY_API_PRIVATE_KEY")?;
    TurnkeyP256ApiKey::from_strings(&private_key, Some(&public_key))
        .context("failed to parse Turnkey API key")
}

fn load_base_url_from_env() -> String {
    env::var("TURNKEY_API_BASE_URL").unwrap_or_else(|_| "https://api.turnkey.com".to_string())
}

// --- Setup ---

async fn setup(output_dir: PathBuf) -> Result<()> {
    let api_key = load_api_key_from_env()?;
    let organization_id =
        env::var("TURNKEY_ORGANIZATION_ID").context("missing TURNKEY_ORGANIZATION_ID")?;
    let api_url = load_base_url_from_env();

    let client = TurnkeyClient::builder()
        .api_key(api_key)
        .base_url(&api_url)
        .build()
        .context("failed to build Turnkey client")?;

    let suffix = format!("{:x}", client.current_timestamp());

    let private_key = client
        .create_private_keys(
            organization_id.clone(),
            client.current_timestamp(),
            activity::CreatePrivateKeysIntentV2 {
                private_keys: vec![activity::PrivateKeyParams {
                    private_key_name: format!("demo-signer-{suffix}-key"),
                    curve: Curve::Ed25519.into(),
                    private_key_tags: Vec::new(),
                    address_formats: vec![AddressFormat::Solana.into()],
                }],
            },
        )
        .await
        .map_err(|e| anyhow!("failed to create private key: {e}"))?
        .result
        .private_keys
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("Turnkey did not return the created private key"))?;

    let agent_key = TurnkeyP256ApiKey::generate();
    let agent_public_key = hex::encode(agent_key.compressed_public_key());
    let agent_private_key = hex::encode(agent_key.private_key());

    let user_id = client
        .create_users(
            organization_id.clone(),
            client.current_timestamp(),
            activity::CreateUsersIntentV4 {
                users: vec![activity::UserParamsV4 {
                    user_name: format!("demo-agent-{suffix}"),
                    user_email: Some(format!("agent-{suffix}@demo.local")),
                    user_phone_number: None,
                    api_keys: vec![activity::ApiKeyParamsV2 {
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
        .map_err(|e| anyhow!("failed to create user: {e}"))?
        .result
        .user_ids
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("Turnkey did not return the created user ID"))?;

    let policy = client
        .create_policy(
            organization_id.clone(),
            client.current_timestamp(),
            activity::CreatePolicyIntentV3 {
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
        .map_err(|e| anyhow!("failed to create policy: {e}"))?
        .result;

    let state = DemoState {
        organization_id,
        api_url,
        private_key_id: private_key.private_key_id,
        agent_user_id: user_id,
        policy_id: policy.policy_id,
        agent_api_public_key: agent_public_key,
        agent_api_private_key: agent_private_key,
    };

    tokio::fs::create_dir_all(&output_dir)
        .await
        .with_context(|| format!("failed to create {}", output_dir.display()))?;
    write_state(&output_dir, &state).await?;
    write_agent_env(&output_dir, &state).await?;

    println!("Setup complete. Artifacts written to {}", output_dir.display());
    println!("\nNext step:");
    println!(
        "  cargo run -p tk --example consensus_demo -- sign --output-dir {}",
        output_dir.display()
    );

    Ok(())
}

// --- Sign ---

async fn sign(payload: String, output_dir: PathBuf) -> Result<()> {
    let state = read_state(&output_dir).await?;

    let api_key = TurnkeyP256ApiKey::from_strings(
        &state.agent_api_private_key,
        Some(&state.agent_api_public_key),
    )
    .context("failed to parse agent API key")?;

    let client = TurnkeyClient::builder()
        .api_key(api_key)
        .base_url(&state.api_url)
        .build()
        .context("failed to build Turnkey client")?;

    match client
        .sign_raw_payload(
            state.organization_id.clone(),
            client.current_timestamp(),
            SignRawPayloadIntentV2 {
                sign_with: state.private_key_id.clone(),
                payload: hex::encode(payload.as_bytes()),
                encoding: PayloadEncoding::Hexadecimal,
                hash_function: HashFunction::NotApplicable,
            },
        )
        .await
    {
        Ok(result) => {
            println!(
                "Signing succeeded (r={}, s={})",
                result.result.r, result.result.s
            );
        }
        Err(TurnkeyClientError::ActivityRequiresApproval(activity_id)) => {
            let fingerprint =
                get_activity_fingerprint(&client, &state.organization_id, &activity_id).await;
            match fingerprint {
                Ok(fp) => {
                    println!("Signing requires consensus approval (fingerprint: {fp})");
                    println!("\nApprove with:");
                    println!("  cargo run -p tk -- activity approve {fp}");
                }
                Err(_) => {
                    println!(
                        "Signing requires consensus approval (activity id: {activity_id})"
                    );
                }
            }
        }
        Err(e) => return Err(anyhow!("signing failed: {e}")),
    }

    Ok(())
}

async fn get_activity_fingerprint(
    client: &TurnkeyClient<TurnkeyP256ApiKey>,
    organization_id: &str,
    activity_id: &str,
) -> Result<String> {
    let response = client
        .get_activity(GetActivityRequest {
            organization_id: organization_id.to_string(),
            activity_id: activity_id.to_string(),
        })
        .await
        .map_err(|e| anyhow!("failed to fetch activity: {e}"))?;

    let activity = response
        .activity
        .ok_or_else(|| anyhow!("Turnkey did not return an activity object"))?;

    if activity.fingerprint.is_empty() {
        return Err(anyhow!("activity fingerprint was empty"));
    }

    Ok(activity.fingerprint)
}

// --- Teardown ---

async fn teardown(output_dir: PathBuf) -> Result<()> {
    let state = read_state(&output_dir).await?;
    let api_key = load_api_key_from_env()?;

    let client = TurnkeyClient::builder()
        .api_key(api_key)
        .base_url(&state.api_url)
        .build()
        .context("failed to build Turnkey client")?;

    client
        .delete_policy(
            state.organization_id.clone(),
            client.current_timestamp(),
            activity::DeletePolicyIntent {
                policy_id: state.policy_id.clone(),
            },
        )
        .await
        .map_err(|e| anyhow!("failed to delete policy: {e}"))?;

    client
        .delete_users(
            state.organization_id.clone(),
            client.current_timestamp(),
            activity::DeleteUsersIntent {
                user_ids: vec![state.agent_user_id.clone()],
            },
        )
        .await
        .map_err(|e| anyhow!("failed to delete users: {e}"))?;

    client
        .delete_private_keys(
            state.organization_id.clone(),
            client.current_timestamp(),
            activity::DeletePrivateKeysIntent {
                private_key_ids: vec![state.private_key_id.clone()],
                delete_without_export: Some(true),
            },
        )
        .await
        .map_err(|e| anyhow!("failed to delete private keys: {e}"))?;

    if tokio::fs::try_exists(&output_dir).await? {
        tokio::fs::remove_dir_all(&output_dir)
            .await
            .with_context(|| format!("failed to remove {}", output_dir.display()))?;
    }

    println!("Teardown complete.");
    Ok(())
}

// --- State helpers ---

async fn write_state(output_dir: &Path, state: &DemoState) -> Result<()> {
    let rendered = serde_json::to_vec_pretty(state).context("failed to serialize state")?;
    let path = output_dir.join("state.json");
    tokio::fs::write(&path, rendered)
        .await
        .with_context(|| format!("failed to write {}", path.display()))
}

async fn read_state(output_dir: &Path) -> Result<DemoState> {
    let path = output_dir.join("state.json");
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
    let path = output_dir.join("agent.env");
    tokio::fs::write(&path, contents)
        .await
        .with_context(|| format!("failed to write {}", path.display()))
}
