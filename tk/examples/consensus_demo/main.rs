use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use regex::Regex;
use serde::Deserialize;
use tokio::process::Command;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::TurnkeyClient;
use turnkey_client::generated::immutable::activity::v1 as activity;
use turnkey_client::generated::immutable::common::v1::Effect;

#[derive(Debug, Parser)]
#[command(about = "Consensus signing demo using two static tk config files.")]
struct Cli {
    /// Path to root/human tk config TOML.
    #[arg(long, default_value = "./human.toml")]
    human_config: PathBuf,

    /// Path to non-root/agent tk config TOML.
    #[arg(long, default_value = "./agent.toml")]
    agent_config: PathBuf,

    /// Namespace passed to `tk ssh git-sign -n`.
    #[arg(long, default_value = "git")]
    namespace: String,

    /// Payload written to a temp file and signed by the agent.
    #[arg(long, default_value = "hello world")]
    payload: String,
}

#[derive(Debug, Deserialize)]
struct ConfigFile {
    turnkey: Option<TurnkeyConfig>,
}

#[derive(Debug, Deserialize)]
struct TurnkeyConfig {
    organization_id: Option<String>,
    api_public_key: Option<String>,
    api_private_key: Option<String>,
    private_key_id: Option<String>,
    api_base_url: Option<String>,
}

#[derive(Debug, Clone)]
struct RequiredConfig {
    organization_id: String,
    api_public_key: String,
    api_private_key: String,
    private_key_id: String,
    api_base_url: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let human = load_required_config(&cli.human_config, "human")?;
    let agent = load_required_config(&cli.agent_config, "agent")?;

    ensure_same_org(&human, &agent)?;

    let policy_id = create_consensus_policy(&human).await?;
    println!("Created consensus policy: {policy_id}");

    let demo_dir = std::env::temp_dir().join("tk-consensus-demo");
    tokio::fs::create_dir_all(&demo_dir)
        .await
        .with_context(|| format!("failed to create {}", demo_dir.display()))?;

    let pub_key_path = demo_dir.join("agent-key.pub");
    let payload_path = demo_dir.join("payload.txt");

    let public_key = run_tk(&cli.agent_config, ["ssh", "public-key"]).await?;
    tokio::fs::write(&pub_key_path, format!("{}\n", public_key.trim()))
        .await
        .with_context(|| format!("failed to write {}", pub_key_path.display()))?;

    tokio::fs::write(&payload_path, &cli.payload)
        .await
        .with_context(|| format!("failed to write {}", payload_path.display()))?;

    let sign_output = run_tk_expect_failure(
        &cli.agent_config,
        [
            "ssh",
            "git-sign",
            "-Y",
            "sign",
            "-n",
            &cli.namespace,
            "-f",
            pub_key_path
                .to_str()
                .ok_or_else(|| anyhow!("non-utf8 pub key path"))?,
            payload_path
                .to_str()
                .ok_or_else(|| anyhow!("non-utf8 payload path"))?,
        ],
    )
    .await?;

    println!("git-sign output:\n{sign_output}");

    let activity_id = parse_activity_id(&sign_output)?;
    let fingerprint = parse_fingerprint(&sign_output)?;

    println!("Parsed activity id: {activity_id}");
    println!("Parsed fingerprint: {fingerprint}");

    run_tk(&cli.human_config, ["activity", "approve", &fingerprint]).await?;

    println!("Approved consensus activity as human: {activity_id}");
    println!("Done. Note: cleanup is manual until resource lifecycle commands are available.");

    Ok(())
}

fn load_required_config(path: &Path, label: &str) -> Result<RequiredConfig> {
    if !path.exists() {
        bail!(
            "missing {label} config at {}. Create it first (see README).",
            path.display()
        );
    }

    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {} config: {}", label, path.display()))?;

    let parsed: ConfigFile = toml::from_str(&raw)
        .with_context(|| format!("failed to parse {} config TOML: {}", label, path.display()))?;

    let turnkey = parsed
        .turnkey
        .ok_or_else(|| anyhow!("{} config is missing [turnkey] section", label))?;

    let organization_id = require_field(turnkey.organization_id, label, "turnkey.organization_id")?;
    let api_public_key = require_field(turnkey.api_public_key, label, "turnkey.api_public_key")?;
    let api_private_key = require_field(turnkey.api_private_key, label, "turnkey.api_private_key")?;
    let private_key_id = require_field(turnkey.private_key_id, label, "turnkey.private_key_id")?;
    let api_base_url = turnkey
        .api_base_url
        .unwrap_or_else(|| "https://api.turnkey.com".to_string());

    Ok(RequiredConfig {
        organization_id,
        api_public_key,
        api_private_key,
        private_key_id,
        api_base_url,
    })
}

fn require_field(value: Option<String>, label: &str, field: &str) -> Result<String> {
    let value = value.unwrap_or_default();
    if value.trim().is_empty() {
        bail!("{} config missing required {}", label, field);
    }
    Ok(value)
}

fn ensure_same_org(human: &RequiredConfig, agent: &RequiredConfig) -> Result<()> {
    if human.organization_id != agent.organization_id {
        bail!(
            "human/agent configs must target the same org (human={}, agent={})",
            human.organization_id,
            agent.organization_id
        );
    }

    if human.api_base_url != agent.api_base_url {
        bail!(
            "human/agent configs must use same api_base_url (human={}, agent={})",
            human.api_base_url,
            agent.api_base_url
        );
    }

    Ok(())
}

async fn create_consensus_policy(human: &RequiredConfig) -> Result<String> {
    let api_key =
        TurnkeyP256ApiKey::from_strings(&human.api_private_key, Some(&human.api_public_key))
            .context("failed to parse human API key")?;

    let client = TurnkeyClient::builder()
        .api_key(api_key)
        .base_url(&human.api_base_url)
        .build()
        .context("failed to build Turnkey client")?;

    let suffix = format!("{:x}", client.current_timestamp());

    let response = client
        .create_policy(
            human.organization_id.clone(),
            client.current_timestamp(),
            activity::CreatePolicyIntentV3 {
                policy_name: format!("consensus-demo-{suffix}"),
                effect: Effect::Allow.into(),
                condition: Some(format!(
                    "private_key.id == '{}' && activity.action == 'SIGN'",
                    human.private_key_id
                )),
                consensus: Some("approvers.count() >= 2".to_string()),
                notes: "consensus demo policy created by tk/examples/consensus_demo".to_string(),
            },
        )
        .await
        .map_err(|e| anyhow!("failed to create consensus policy: {e}"))?;

    Ok(response.result.policy_id)
}

async fn run_tk<I, S>(config_path: &Path, args: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args = args
        .into_iter()
        .map(|s| s.as_ref().to_string())
        .collect::<Vec<_>>();

    let output = Command::new("cargo")
        .arg("run")
        .arg("-p")
        .arg("tk")
        .arg("--quiet")
        .arg("--")
        .args(&args)
        .env("TURNKEY_TK_CONFIG_PATH", config_path)
        .output()
        .await
        .with_context(|| format!("failed to run tk command: tk {}", args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "tk command failed: tk {}\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            stdout,
            stderr
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn run_tk_expect_failure<I, S>(config_path: &Path, args: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args = args
        .into_iter()
        .map(|s| s.as_ref().to_string())
        .collect::<Vec<_>>();

    let output = Command::new("cargo")
        .arg("run")
        .arg("-p")
        .arg("tk")
        .arg("--quiet")
        .arg("--")
        .args(&args)
        .env("TURNKEY_TK_CONFIG_PATH", config_path)
        .output()
        .await
        .with_context(|| format!("failed to run tk command: tk {}", args.join(" ")))?;

    let merged = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    if output.status.success() {
        bail!(
            "expected git-sign to require consensus, but command succeeded:\n{}",
            merged
        );
    }

    Ok(merged)
}

fn parse_activity_id(output: &str) -> Result<String> {
    let re = Regex::new(r"activity id:\s*([A-Za-z0-9_-]+)")?;
    let caps = re
        .captures(output)
        .ok_or_else(|| anyhow!("could not find `activity id` in git-sign output"))?;
    Ok(caps
        .get(1)
        .ok_or_else(|| anyhow!("activity id capture missing"))?
        .as_str()
        .to_string())
}

fn parse_fingerprint(output: &str) -> Result<String> {
    let re = Regex::new(r"fingerprint:\s*([A-Za-z0-9_-]+)")?;
    let caps = re
        .captures(output)
        .ok_or_else(|| anyhow!("could not find `fingerprint` in git-sign output"))?;
    Ok(caps
        .get(1)
        .ok_or_else(|| anyhow!("fingerprint capture missing"))?
        .as_str()
        .to_string())
}
