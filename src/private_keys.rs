//! The `private-key` commands: list, fetch, and create private keys.

use std::str::FromStr;

use anyhow::Result;
use clap::{ArgGroup, Args, Subcommand, ValueEnum};
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
    /// Name of the single private key to create.
    #[arg(long, requires = "curve")]
    name: Option<String>,
    /// Curve of the private key.
    #[arg(long, value_enum, requires = "name")]
    curve: Option<CurveArg>,
    /// Address format to derive from the key, such as `ethereum`.
    #[arg(long = "address-format", value_name = "FORMAT", requires = "name")]
    address_formats: Vec<AddressFormatArg>,
    /// Tag ID to attach.
    #[arg(long = "tag", requires = "name")]
    tags: Vec<Uuid>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CurveArg {
    Secp256k1,
    Ed25519,
    P256,
}

#[derive(Clone, Copy, Debug)]
pub struct AddressFormatArg(AddressFormat);

impl FromStr for AddressFormatArg {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let upper = text.to_ascii_uppercase().replace('-', "_");
        let full = if upper.starts_with("ADDRESS_FORMAT_") {
            upper
        } else {
            format!("ADDRESS_FORMAT_{upper}")
        };
        match AddressFormat::from_str_name(&full) {
            Some(AddressFormat::Unspecified) | None => {
                Err(format!("unknown address format {text:?}"))
            }
            Some(format) => Ok(Self(format)),
        }
    }
}

pub enum PreparedPrivateKeyCommand {
    List,
    Get(Uuid),
    Create(CreatePrivateKeysIntentV2),
}

impl PrivateKeyCommand {
    pub fn prepare(self) -> Result<PreparedPrivateKeyCommand> {
        Ok(match self {
            Self::List => PreparedPrivateKeyCommand::List,
            Self::Get { id } => PreparedPrivateKeyCommand::Get(id),
            Self::Create(CreatePrivateKeyArgs {
                name: Some(private_key_name),
                curve: Some(curve),
                address_formats,
                tags,
                ..
            }) => PreparedPrivateKeyCommand::Create(CreatePrivateKeysIntentV2 {
                private_keys: vec![PrivateKeyParams {
                    private_key_name,
                    curve: match curve {
                        CurveArg::Secp256k1 => Curve::Secp256k1,
                        CurveArg::Ed25519 => Curve::Ed25519,
                        CurveArg::P256 => Curve::P256,
                    },
                    private_key_tags: tags.iter().map(ToString::to_string).collect(),
                    address_formats: address_formats
                        .into_iter()
                        .map(|AddressFormatArg(format)| format)
                        .collect(),
                }],
            }),
            Self::Create(CreatePrivateKeyArgs {
                name: Some(_),
                curve: None,
                ..
            }) => unreachable!("clap requires --curve with --name"),
            Self::Create(CreatePrivateKeyArgs {
                body, name: None, ..
            }) => {
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
            Self::List => {
                let client = build_turnkey_client(auth.stamper, &auth.api_base_url)?;
                let data = client
                    .get_private_keys(GetPrivateKeysRequest {
                        organization_id: auth.org_id.to_string(),
                    })
                    .await?;
                Ok(OperationOutput::result("private-key.list", to_value(data)?))
            }
            Self::Get(id) => {
                let client = build_turnkey_client(auth.stamper, &auth.api_base_url)?;
                let data = client
                    .get_private_key(GetPrivateKeyRequest {
                        organization_id: auth.org_id.to_string(),
                        private_key_id: id.to_string(),
                    })
                    .await?;
                if data.private_key.is_none() {
                    return Err(MissingResource::new("private key", id.to_string()).into());
                }
                Ok(OperationOutput::result("private-key.get", to_value(data)?))
            }
            Self::Create(params) => {
                submit_activity(
                    &auth,
                    "private-key.create",
                    "create_private_keys",
                    "ACTIVITY_TYPE_CREATE_PRIVATE_KEYS_V2",
                    &to_value(params)?,
                )
                .await
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
                "private-key create --name k --curve nope",
                ErrorKind::InvalidValue,
            ),
            (
                "private-key create --name k --curve ed25519 --address-format nope",
                ErrorKind::ValueValidation,
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
            "private-key create --name k --curve secp256k1 --address-format ethereum --address-format ADDRESS_FORMAT_SOLANA --tag {tag}"
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
                "addressFormats": ["ADDRESS_FORMAT_ETHEREUM", "ADDRESS_FORMAT_SOLANA"],
            }]})
        );
    }

    #[test]
    fn an_empty_parameters_object_is_rejected_before_auth() {
        let error = parse(r#"private-key create --input-json {"privateKeys":[]}"#)
            .unwrap()
            .command
            .prepare()
            .err()
            .expect("prepare should have failed");
        assert_eq!(
            error.to_string(),
            "privateKeys must contain at least one private key"
        );
    }
}
