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
    /// Config key to read, for example `turnkey.organizationId`.
    key: ConfigKey,
}

#[derive(Debug, ClapArgs)]
struct SetArgs {
    /// Config key to write, for example `turnkey.organizationId`.
    key: ConfigKey,
    /// Value to persist for the key.
    value: String,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct ConfigValue {
    pub key: String,
    pub value: String,
}

impl Display for ConfigValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.value)
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct ConfigValueSet {
    pub key: String,
}

impl Display for ConfigValueSet {
    fn fmt(&self, _: &mut Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct ConfigListed {
    pub config: RedactedConfig,
}

impl Display for ConfigListed {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let rendered = serde_json::to_string_pretty(&self.config).map_err(|_| fmt::Error)?;
        f.write_str(&rendered)
    }
}

pub async fn run(_ctx: &mut StdCtx, args: Args) -> anyhow::Result<Outcome> {
    Ok(match args.command {
        Command::Get(GetArgs { key }) => Outcome::ConfigValue(ConfigValue {
            value: config::get_resolved_config_value(key).await?,
            key: key.to_string(),
        }),
        Command::Set(SetArgs { key, value }) => {
            config::set_config_value(key, &value).await?;
            Outcome::ConfigValueSet(ConfigValueSet {
                key: key.to_string(),
            })
        }
        Command::List => Outcome::ConfigListed(ConfigListed {
            config: config::redacted_config().await?,
        }),
    })
}
