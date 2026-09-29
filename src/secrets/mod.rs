mod delete;
mod env;
mod export;
mod import;
mod input;

use anyhow::Result;
use clap::{ArgGroup, Args, Subcommand};
use serde::{Serialize, Serializer};
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::PathBuf;
use turnkey_client::generated::immutable::models::v1::KeyValue;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::auth::ResolvedAuth;
use crate::errors::InvalidInput;
use crate::operations::OperationOutput;
use input::{SecretName, SecretRef, Selector, UniqueKeyValues, parse_key_value, read_value};

#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    /// List secret metadata; values are never returned.
    List {
        /// Page size, or the most matches to return when filtering.
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: u32,
        /// Secret ID to continue after.
        #[arg(long)]
        cursor: Option<Uuid>,
        /// Only secrets carrying this static property; every given property must match.
        #[arg(long = "property", value_name = "KEY=VALUE", value_parser = parse_key_value)]
        properties: Vec<KeyValue>,
        /// Only secrets whose name starts with this prefix, for example hermes/.
        #[arg(long)]
        name_prefix: Option<String>,
    },
    /// Encrypt and import a new named secret.
    Import {
        /// Name of the new secret.
        #[arg(long, value_parser = SecretName::parse_new)]
        name: SecretName,
        /// File holding the secret value.
        #[arg(long)]
        from_file: Option<PathBuf>,
        /// Policy-visible property bound to the secret.
        #[arg(long = "property", value_name = "KEY=VALUE", value_parser = parse_key_value)]
        properties: Vec<KeyValue>,
    },
    /// Export every matching secret as dotenv lines.
    ///
    /// Secret names are `PREFIX/VAR`; `VAR` becomes the line's key.
    #[command(group = ArgGroup::new("selector").required(true).multiple(true))]
    Env {
        /// Only secrets carrying this static property; every given property must match.
        #[arg(long = "property", value_name = "KEY=VALUE", value_parser = parse_key_value, group = "selector")]
        properties: Vec<KeyValue>,
        /// Only secrets whose name starts with this prefix, for example hermes/.
        #[arg(long, group = "selector")]
        name_prefix: Option<String>,
    },
    /// Delete a secret.
    Delete {
        #[command(flatten)]
        secret: SecretSelector,
    },
    /// Export a secret's value.
    Export {
        #[command(flatten)]
        secret: SecretSelector,
        /// Write the value to this new file (0600) instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Policy-visible context for this export request only.
        #[arg(long = "context", value_name = "KEY=VALUE", value_parser = parse_key_value)]
        context: Vec<KeyValue>,
    },
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct SecretSelector {
    /// Name of the secret.
    #[arg(long, value_parser = SecretName::parse)]
    name: Option<SecretName>,
    /// ID of the secret.
    #[arg(long)]
    id: Option<Uuid>,
}

impl From<SecretSelector> for SecretRef {
    fn from(selector: SecretSelector) -> Self {
        match selector {
            SecretSelector { id: Some(id), .. } => Self::Id(id),
            SecretSelector {
                name: Some(name), ..
            } => Self::Name(name),
            SecretSelector {
                name: None,
                id: None,
            } => {
                unreachable!("clap requires exactly one of --name or --id")
            }
        }
    }
}

pub enum PreparedSecret {
    List {
        limit: u32,
        listing: Listing,
    },
    Import {
        name: SecretName,
        value: Zeroizing<String>,
        properties: UniqueKeyValues,
    },
    Export {
        secret: SecretRef,
        out: Option<PathBuf>,
        context: UniqueKeyValues,
    },
    Env {
        selector: Selector,
    },
    Delete {
        secret: SecretRef,
    },
}

pub enum Listing {
    Page(Option<Uuid>),
    Filtered {
        after: Option<Uuid>,
        selector: Selector,
    },
}

impl SecretCommand {
    /// Validates arguments and reads input before resolving credentials.
    pub fn prepare(self, non_interactive: bool) -> Result<PreparedSecret> {
        Ok(match self {
            Self::List {
                limit,
                cursor,
                properties,
                name_prefix,
            } => {
                let listing = if properties.is_empty() && name_prefix.is_none() {
                    Listing::Page(cursor)
                } else {
                    Listing::Filtered {
                        after: cursor,
                        selector: Selector::new(
                            UniqueKeyValues::parse(properties, "--property")?,
                            name_prefix,
                        ),
                    }
                };
                PreparedSecret::List { limit, listing }
            }
            Self::Import {
                name,
                from_file,
                properties,
            } => {
                let properties = UniqueKeyValues::parse(properties, "--property")?;
                let value = read_value(from_file.as_deref(), non_interactive)?;
                PreparedSecret::Import {
                    name,
                    value,
                    properties,
                }
            }
            Self::Delete { secret } => PreparedSecret::Delete {
                secret: secret.into(),
            },
            Self::Env {
                properties,
                name_prefix,
            } => PreparedSecret::Env {
                selector: Selector::new(
                    UniqueKeyValues::parse(properties, "--property")?,
                    name_prefix,
                ),
            },
            Self::Export {
                secret,
                out,
                context,
            } => {
                if let Some(path) = &out
                    && fs::symlink_metadata(path).is_ok()
                {
                    return Err(
                        InvalidInput(format!("refusing to overwrite {}", path.display())).into(),
                    );
                }
                PreparedSecret::Export {
                    secret: secret.into(),
                    out,
                    context: UniqueKeyValues::parse(context, "--context")?,
                }
            }
        })
    }
}

pub struct SecretOutput {
    record: OperationOutput,
    plain: Option<Zeroizing<String>>,
}

impl From<OperationOutput> for SecretOutput {
    fn from(record: OperationOutput) -> Self {
        Self {
            record,
            plain: None,
        }
    }
}

impl Serialize for SecretOutput {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.record.serialize(serializer)
    }
}

impl Display for SecretOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.plain {
            Some(value) => f.write_str(value),
            None => self.record.fmt(f),
        }
    }
}

impl PreparedSecret {
    pub async fn run(self, auth: ResolvedAuth) -> Result<SecretOutput> {
        match self {
            Self::List { limit, listing } => {
                export::list(auth, limit, listing).await.map(Into::into)
            }
            Self::Import {
                name,
                value,
                properties,
            } => import::run(auth, name, value, properties)
                .await
                .map(Into::into),
            Self::Export {
                secret,
                out,
                context,
            } => export::run(auth, secret, out, context).await,
            Self::Env { selector } => env::run(auth, selector).await,
            Self::Delete { secret } => delete::run(auth, secret).await.map(Into::into),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use clap::error::ErrorKind;

    #[derive(Debug, Parser)]
    struct Cli {
        #[command(subcommand)]
        command: SecretCommand,
    }

    fn parse(args: &[&str]) -> Result<SecretRef, clap::Error> {
        let cli = Cli::try_parse_from(["tk"].into_iter().chain(args.iter().copied()))?;
        match cli.command {
            SecretCommand::Export { secret, .. } => Ok(secret.into()),
            other => panic!("expected an export command, parsed {other:?}"),
        }
    }

    #[test]
    fn list_parses_typed_filters_and_cursor() {
        let id = Uuid::new_v4().to_string();
        let parse =
            |args: &[&str]| Cli::try_parse_from(["tk"].into_iter().chain(args.iter().copied()));
        let filtered = parse(&["list", "--property", "env=prod", "--name-prefix", "svc/"]).unwrap();
        let SecretCommand::List {
            limit: 50,
            cursor: None,
            properties,
            name_prefix: Some(prefix),
        } = filtered.command
        else {
            panic!("expected a filtered list, parsed {:?}", filtered.command)
        };
        assert_eq!(
            properties,
            [KeyValue {
                key: "env".into(),
                value: "prod".into()
            }]
        );
        assert_eq!(prefix, "svc/");
        let paged = parse(&["list", "--limit", "10", "--cursor", &id]).unwrap();
        let SecretCommand::List {
            limit: 10,
            cursor: Some(cursor),
            properties,
            name_prefix: None,
        } = paged.command
        else {
            panic!("expected a paged list, parsed {:?}", paged.command)
        };
        assert_eq!(cursor.to_string(), id);
        assert!(properties.is_empty());
    }

    #[test]
    fn export_selects_a_secret_by_exactly_one_of_name_or_id() {
        let id = Uuid::new_v4();
        assert_eq!(
            parse(&["export", "--name", "api-token"]).unwrap(),
            SecretRef::Name(SecretName::parse("api-token").unwrap())
        );
        assert_eq!(
            parse(&["export", "--id", &id.to_string()]).unwrap(),
            SecretRef::Id(id)
        );
        assert_eq!(
            parse(&["export"]).unwrap_err().kind(),
            ErrorKind::MissingRequiredArgument
        );
        assert_eq!(
            parse(&["export", "--name", "api-token", "--id", &id.to_string()])
                .unwrap_err()
                .kind(),
            ErrorKind::ArgumentConflict
        );
        assert_eq!(
            parse(&["export", "--id", "api-token"]).unwrap_err().kind(),
            ErrorKind::ValueValidation
        );
        assert_eq!(
            parse(&["export", "api-token"]).unwrap_err().kind(),
            ErrorKind::UnknownArgument
        );
    }
}
