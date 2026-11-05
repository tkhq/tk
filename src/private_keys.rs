//! The `private-key` commands: list, fetch, and create private keys.

use std::{ffi::OsStr, sync::LazyLock};

use anyhow::Result;
use clap::{
    Arg, ArgGroup, Args, Command, Subcommand, ValueEnum,
    builder::{PossibleValue, PossibleValuesParser, TypedValueParser},
    error::ErrorKind,
};
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
    /// Address format to derive from the key.
    #[arg(
        long = "address-format",
        value_name = "FORMAT",
        value_parser = AddressFormatParser,
        requires = "name"
    )]
    address_formats: Vec<AddressFormat>,
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

const ADDRESS_FORMATS: [AddressFormat; 38] = [
    AddressFormat::Uncompressed,
    AddressFormat::Compressed,
    AddressFormat::Ethereum,
    AddressFormat::Solana,
    AddressFormat::Cosmos,
    AddressFormat::Tron,
    AddressFormat::Sui,
    AddressFormat::Aptos,
    AddressFormat::BitcoinMainnetP2pkh,
    AddressFormat::BitcoinMainnetP2sh,
    AddressFormat::BitcoinMainnetP2wpkh,
    AddressFormat::BitcoinMainnetP2wsh,
    AddressFormat::BitcoinMainnetP2tr,
    AddressFormat::BitcoinTestnetP2pkh,
    AddressFormat::BitcoinTestnetP2sh,
    AddressFormat::BitcoinTestnetP2wpkh,
    AddressFormat::BitcoinTestnetP2wsh,
    AddressFormat::BitcoinTestnetP2tr,
    AddressFormat::BitcoinSignetP2pkh,
    AddressFormat::BitcoinSignetP2sh,
    AddressFormat::BitcoinSignetP2wpkh,
    AddressFormat::BitcoinSignetP2wsh,
    AddressFormat::BitcoinSignetP2tr,
    AddressFormat::BitcoinRegtestP2pkh,
    AddressFormat::BitcoinRegtestP2sh,
    AddressFormat::BitcoinRegtestP2wpkh,
    AddressFormat::BitcoinRegtestP2wsh,
    AddressFormat::BitcoinRegtestP2tr,
    AddressFormat::Sei,
    AddressFormat::Xlm,
    AddressFormat::DogeMainnet,
    AddressFormat::DogeTestnet,
    AddressFormat::TonV3r2,
    AddressFormat::TonV4r2,
    AddressFormat::TonV5r1,
    AddressFormat::Xrp,
    AddressFormat::SparkMainnet,
    AddressFormat::SparkRegtest,
];

fn address_format_name(format: AddressFormat) -> String {
    let name = format.as_str_name();
    name.strip_prefix("ADDRESS_FORMAT_")
        .unwrap_or(name)
        .to_ascii_lowercase()
        .replace('_', "-")
}

static ADDRESS_FORMAT_NAMES: LazyLock<Vec<(String, AddressFormat)>> = LazyLock::new(|| {
    ADDRESS_FORMATS
        .into_iter()
        .map(|format| (address_format_name(format), format))
        .collect()
});

#[derive(Clone, Copy)]
struct AddressFormatParser;

impl TypedValueParser for AddressFormatParser {
    type Value = AddressFormat;

    fn parse_ref(
        &self,
        cmd: &Command,
        arg: Option<&Arg>,
        value: &OsStr,
    ) -> Result<AddressFormat, clap::Error> {
        let name =
            PossibleValuesParser::new(ADDRESS_FORMAT_NAMES.iter().map(|(name, _)| name.as_str()))
                .parse_ref(cmd, arg, value)?;
        ADDRESS_FORMAT_NAMES
            .iter()
            .find_map(|(candidate, format)| (*candidate == name).then_some(*format))
            .ok_or_else(|| {
                cmd.clone()
                    .error(ErrorKind::InvalidValue, "unknown address format")
            })
    }

    fn possible_values(&self) -> Option<Box<dyn Iterator<Item = PossibleValue> + '_>> {
        Some(Box::new(
            ADDRESS_FORMAT_NAMES
                .iter()
                .map(|(name, _)| PossibleValue::new(name.as_str())),
        ))
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
                    address_formats,
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
                    &params,
                )
                .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

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

    #[test]
    fn address_formats_cover_every_specified_variant_with_unique_kebab_names() {
        let mut discriminants: Vec<i32> = ADDRESS_FORMATS.iter().map(|&f| f as i32).collect();
        discriminants.sort_unstable();
        assert_eq!(discriminants, (1..=38).collect::<Vec<_>>());
        let mut names: Vec<&str> = ADDRESS_FORMAT_NAMES
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 38);
        assert!(names.contains(&"ton-v3r2"));
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
