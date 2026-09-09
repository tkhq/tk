use clap::{Args as ClapArgs, Subcommand};
use serde::Serialize;
use std::fmt::{self, Display, Formatter};

use crate::outcome::Outcome;
use crate::output::StdCtx;
use turnkey_auth::config::{self, ConfigKey, RedactedConfig};

/// Arguments for the `tk config` subcommand.
#[derive(Debug, ClapArgs)]
#[command(about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the resolved value for one config key.
    Get(GetArgs),
    /// Persist a config value to the global config file.
    Set(SetArgs),
    /// Print the resolved effective config.
    List,
}

#[derive(Debug, ClapArgs)]
struct GetArgs {
    key: String,
}

#[derive(Debug, ClapArgs)]
struct SetArgs {
    key: String,
    value: String,
}

/// Terminal outcome of `tk config get`.
#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct ConfigValue {
    /// The requested config key.
    pub key: String,
    /// The resolved value, redacted when sensitive.
    pub value: String,
}

impl Display for ConfigValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.value)
    }
}

/// Terminal outcome of `tk config set`. Machine-only: human mode stays silent.
#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct ConfigValueSet {
    /// The persisted config key.
    pub key: String,
}

impl Display for ConfigValueSet {
    fn fmt(&self, _: &mut Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

/// Terminal outcome of `tk config list`: the effective config, redacted.
#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct ConfigListed {
    /// The resolved effective config with sensitive values redacted.
    pub config: RedactedConfig,
}

impl Display for ConfigListed {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let rendered = serde_json::to_string_pretty(&self.config).map_err(|_| fmt::Error)?;
        f.write_str(&rendered)
    }
}

/// Runs the `tk config` subcommand.
pub async fn run(_ctx: &mut StdCtx, args: Args) -> anyhow::Result<Outcome> {
    Ok(match args.command {
        Command::Get(args) => {
            let key = ConfigKey::parse(&args.key)?;
            Outcome::ConfigValue(ConfigValue {
                value: config::get_resolved_config_value(key).await?,
                key: args.key,
            })
        }
        Command::Set(args) => {
            let key = ConfigKey::parse(&args.key)?;
            config::set_config_value(key, &args.value).await?;
            Outcome::ConfigValueSet(ConfigValueSet { key: args.key })
        }
        Command::List => Outcome::ConfigListed(ConfigListed {
            config: config::redacted_config().await?,
        }),
    })
}
