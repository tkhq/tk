//! The `private-key` commands: list, fetch, and create private keys.

use anyhow::Result;
use clap::{ArgGroup, Args, Subcommand};
use serde_json::to_value;
use turnkey_client::generated::{
    GetPrivateKeyRequest, GetPrivateKeysRequest,
    immutable::{
        activity::v1::{CreatePrivateKeysIntentV2, PrivateKeyParams},
        common::v1::{AddressFormat, Curve},
    },
};
use uuid::Uuid;

use crate::{
    auth::{ResolvedAuth, build_turnkey_client},
    enum_args,
    errors::{InvalidInput, MissingResource},
    operations::{OperationOutput, submit_activity},
    resources::BodySource,
};

#[derive(Debug, Subcommand)]
pub enum PrivateKeyCommand {
    /// List private keys.
    List,
    /// Fetch one private key by ID.
    Get {
        /// Private key ID.
        #[arg(long)]
        id: Uuid,
    },
    /// Create a private key from flags, or one or more private keys from a
    /// `CreatePrivateKeysIntentV2` parameters object.
    Create(CreatePrivateKeyArgs),
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("key_source").required(true).args(["input_json", "input_file", "name"])))]
pub struct CreatePrivateKeyArgs {
    #[command(flatten)]
    body: BodySource,
    #[command(flatten)]
    flags: Option<PrivateKeyFlags>,
}

#[derive(Debug, Args)]
struct PrivateKeyFlags {
    /// Name of the single private key to create.
    #[arg(long, required = false, requires = "curve")]
    name: String,
    /// Curve of the private key.
    #[arg(long, required = false, requires = "name", value_parser = enum_args::parser::<Curve>())]
    curve: Curve,
    /// Address format to derive from the key.
    #[arg(long = "address-format", value_name = "FORMAT", value_parser = enum_args::parser::<AddressFormat>(), requires = "name")]
    address_formats: Vec<AddressFormat>,
    /// ID of a private key tag to attach; user tags do not apply to private keys.
    #[arg(long = "tag", requires = "name")]
    tags: Vec<Uuid>,
}

pub enum PreparedPrivateKeyCommand {
    Query(PrivateKeyQuery),
    Create(CreatePrivateKeysIntentV2),
}

pub enum PrivateKeyQuery {
    List,
    Get(Uuid),
}

impl PrivateKeyCommand {
    pub fn prepare(self) -> Result<PreparedPrivateKeyCommand> {
        Ok(match self {
            Self::List => PreparedPrivateKeyCommand::Query(PrivateKeyQuery::List),
            Self::Get { id } => PreparedPrivateKeyCommand::Query(PrivateKeyQuery::Get(id)),
            Self::Create(CreatePrivateKeyArgs {
                flags:
                    Some(PrivateKeyFlags {
                        name: private_key_name,
                        curve,
                        address_formats,
                        tags,
                    }),
                body: _,
            }) => PreparedPrivateKeyCommand::Create(CreatePrivateKeysIntentV2 {
                private_keys: vec![PrivateKeyParams {
                    private_key_name,
                    curve,
                    private_key_tags: tags.iter().map(ToString::to_string).collect(),
                    address_formats,
                }],
            }),
            Self::Create(CreatePrivateKeyArgs { body, flags: None }) => {
                let params: CreatePrivateKeysIntentV2 = body.parse()?;
                if params.private_keys.is_empty() {
                    return Err(InvalidInput(
                        "privateKeys must contain at least one private key".into(),
                    )
                    .into());
                }
                PreparedPrivateKeyCommand::Create(params)
            }
        })
    }
}

impl PreparedPrivateKeyCommand {
    pub async fn run(self, auth: ResolvedAuth) -> Result<OperationOutput> {
        match self {
            Self::Query(query) => query.run(auth).await,
            Self::Create(params) => {
                submit_activity(
                    &auth,
                    "private-key.create",
                    "create_private_keys",
                    "ACTIVITY_TYPE_CREATE_PRIVATE_KEYS_V2",
                    &params,
                )
                .await
            }
        }
    }
}

impl PrivateKeyQuery {
    async fn run(self, auth: ResolvedAuth) -> Result<OperationOutput> {
        let client = build_turnkey_client(auth.stamper, &auth.api_base_url)?;
        let organization_id = auth.org_id.to_string();
        match self {
            Self::List => {
                let data = client
                    .get_private_keys(GetPrivateKeysRequest { organization_id })
                    .await?;
                Ok(OperationOutput::result("private-key.list", to_value(data)?))
            }
            Self::Get(id) => {
                let data = client
                    .get_private_key(GetPrivateKeyRequest {
                        organization_id,
                        private_key_id: id.to_string(),
                    })
                    .await?;
                if data.private_key.is_none() {
                    return Err(MissingResource::new("private key", id.to_string()).into());
                }
                Ok(OperationOutput::result("private-key.get", to_value(data)?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::{Parser, error::ErrorKind};

    use super::*;

    #[derive(Debug, Parser)]
    struct Parsed {
        #[command(subcommand)]
        command: PrivateKeyCommand,
    }

    fn parse(args: &str) -> Result<Parsed, clap::Error> {
        Parsed::try_parse_from(args.split(' '))
    }

    #[test]
    fn invalid_combinations_fail_during_parsing() {
        for (args, kind) in [
            ("private-key create", ErrorKind::MissingRequiredArgument),
            (
                "private-key create --name k",
                ErrorKind::MissingRequiredArgument,
            ),
            (
                "private-key create --curve ed25519",
                ErrorKind::MissingRequiredArgument,
            ),
            (
                "private-key create --address-format ethereum",
                ErrorKind::MissingRequiredArgument,
            ),
            (
                "private-key create --name k --curve nope",
                ErrorKind::InvalidValue,
            ),
            (
                "private-key create --name k --curve CURVE_ED25519",
                ErrorKind::InvalidValue,
            ),
            (
                "private-key create --name k --curve ed25519 --address-format ADDRESS_FORMAT_ETHEREUM",
                ErrorKind::InvalidValue,
            ),
            (
                "private-key create --name k --curve ed25519 --address-format Ethereum",
                ErrorKind::InvalidValue,
            ),
            (
                "private-key create --name k --curve ed25519 --tag not-a-uuid",
                ErrorKind::ValueValidation,
            ),
            (
                "private-key create --name k --curve ed25519 --input-json {}",
                ErrorKind::ArgumentConflict,
            ),
            (
                "private-key create --input-json {} --tag 8d4b1e7a-0c6d-4d1a-9d3e-6b0f1c2d3e4f",
                ErrorKind::MissingRequiredArgument,
            ),
            (
                "private-key create --input-json {} --input-file x",
                ErrorKind::ArgumentConflict,
            ),
            ("private-key get --id nope", ErrorKind::ValueValidation),
            ("private-key get", ErrorKind::MissingRequiredArgument),
        ] {
            assert_eq!(parse(args).unwrap_err().kind(), kind, "{args}");
        }
    }

    #[test]
    fn flags_build_one_private_key_intent() {
        let tag = "8d4b1e7a-0c6d-4d1a-9d3e-6b0f1c2d3e4f";
        let args = format!(
            "private-key create --name k --curve secp256k1 --address-format ethereum --address-format bitcoin-mainnet-p2pkh --tag {tag}"
        );
        let PreparedPrivateKeyCommand::Create(intent) =
            parse(&args).unwrap().command.prepare().unwrap()
        else {
            panic!("expected a create intent")
        };
        assert_eq!(
            to_value(intent).unwrap(),
            serde_json::json!({"privateKeys": [{
                "privateKeyName": "k",
                "curve": "CURVE_SECP256K1",
                "privateKeyTags": [tag],
                "addressFormats": ["ADDRESS_FORMAT_ETHEREUM", "ADDRESS_FORMAT_BITCOIN_MAINNET_P2PKH"],
            }]})
        );
    }
}
