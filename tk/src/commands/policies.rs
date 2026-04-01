use anyhow::{Result, anyhow};
use clap::{Args as ClapArgs, Subcommand, ValueEnum};
use turnkey_client::generated::immutable::activity::v1 as activity;
use turnkey_client::generated::immutable::common::v1::Effect;

#[derive(Debug, ClapArgs)]
#[command(about = "Policy management commands.")]
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
    /// Create a new policy.
    Create(CreateArgs),
    /// Delete a policy.
    Delete(DeleteArgs),
}

#[derive(Debug, ClapArgs)]
struct CreateArgs {
    /// Human-readable name for the policy.
    #[arg(long)]
    name: String,
    /// Policy effect.
    #[arg(long)]
    effect: EffectArg,
    /// CEL condition expression.
    #[arg(long)]
    condition: Option<String>,
    /// CEL consensus expression.
    #[arg(long)]
    consensus: Option<String>,
    /// Policy notes.
    #[arg(long, default_value = "")]
    notes: String,
}

#[derive(Debug, ClapArgs)]
struct DeleteArgs {
    /// Policy ID to delete.
    #[arg(long)]
    policy_id: String,
}

#[derive(Debug, Clone, ValueEnum)]
enum EffectArg {
    Allow,
    Deny,
}

impl From<EffectArg> for Effect {
    fn from(e: EffectArg) -> Self {
        match e {
            EffectArg::Allow => Effect::Allow,
            EffectArg::Deny => Effect::Deny,
        }
    }
}

async fn create(args: CreateArgs) -> Result<()> {
    if matches!(args.effect, EffectArg::Allow)
        && args.condition.is_none()
        && args.consensus.is_none()
    {
        return Err(anyhow!(
            "allow policies must include at least one constraint: --condition or --consensus"
        ));
    }

    let config = turnkey_auth::config::Config::resolve().await?;
    let signer = turnkey_auth::turnkey::TurnkeySigner::new(config)?;
    let client = signer.client();
    let org_id = signer.organization_id().to_string();

    let effect: Effect = args.effect.into();

    let response = client
        .create_policy(
            org_id,
            client.current_timestamp(),
            activity::CreatePolicyIntentV3 {
                policy_name: args.name,
                effect: effect.into(),
                condition: args.condition,
                consensus: args.consensus,
                notes: args.notes,
            },
        )
        .await
        .map_err(|e| anyhow!("failed to create policy: {e}"))?;

    println!(
        "{}",
        serde_json::json!({ "policyId": response.result.policy_id })
    );
    Ok(())
}

async fn delete(args: DeleteArgs) -> Result<()> {
    let config = turnkey_auth::config::Config::resolve().await?;
    let signer = turnkey_auth::turnkey::TurnkeySigner::new(config)?;
    let client = signer.client();
    let org_id = signer.organization_id().to_string();

    client
        .delete_policy(
            org_id,
            client.current_timestamp(),
            activity::DeletePolicyIntent {
                policy_id: args.policy_id.clone(),
            },
        )
        .await
        .map_err(|e| anyhow!("failed to delete policy: {e}"))?;

    println!(
        "{}",
        serde_json::json!({ "deletedPolicyId": args.policy_id })
    );
    Ok(())
}
