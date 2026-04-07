use anyhow::{Result, anyhow};
use clap::{Args as ClapArgs, Subcommand, ValueEnum};
use turnkey_client::generated::immutable::activity::v1 as activity;
use turnkey_client::generated::immutable::common::v1::{AddressFormat, Curve};

#[derive(Debug, ClapArgs)]
#[command(about = "Private key management commands.")]
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
    /// Create a new private key.
    Create(CreateArgs),
    /// Delete one or more private keys.
    Delete(DeleteArgs),
}

#[derive(Debug, ClapArgs)]
struct CreateArgs {
    /// Human-readable name for the private key.
    #[arg(long)]
    name: String,
    /// Cryptographic curve for the key.
    #[arg(long)]
    curve: CurveArg,
    /// Tag IDs to associate with the key.
    #[arg(long = "tag")]
    tags: Vec<String>,
    /// Address formats to derive.
    #[arg(long = "address-format")]
    address_formats: Vec<AddressFormatArg>,
}

#[derive(Debug, ClapArgs)]
struct DeleteArgs {
    /// Private key IDs to delete.
    #[arg(long = "key-id", required = true)]
    key_ids: Vec<String>,
    /// Allow deletion without requiring a prior export.
    #[arg(long, default_value_t = false)]
    delete_without_export: bool,
}

#[derive(Debug, Clone, ValueEnum)]
enum CurveArg {
    Ed25519,
    Secp256k1,
    P256,
}

impl From<CurveArg> for Curve {
    fn from(c: CurveArg) -> Self {
        match c {
            CurveArg::Ed25519 => Curve::Ed25519,
            CurveArg::Secp256k1 => Curve::Secp256k1,
            CurveArg::P256 => Curve::P256,
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
#[allow(non_camel_case_types)]
enum AddressFormatArg {
    Uncompressed,
    Compressed,
    Ethereum,
    Solana,
    Cosmos,
    Tron,
    Sui,
    Aptos,
    BitcoinMainnetP2pkh,
    BitcoinMainnetP2sh,
    BitcoinMainnetP2wpkh,
    BitcoinMainnetP2wsh,
    BitcoinMainnetP2tr,
    BitcoinTestnetP2pkh,
    BitcoinTestnetP2sh,
    BitcoinTestnetP2wpkh,
    BitcoinTestnetP2wsh,
    BitcoinTestnetP2tr,
    BitcoinSignetP2pkh,
    BitcoinSignetP2sh,
    BitcoinSignetP2wpkh,
    BitcoinSignetP2wsh,
    BitcoinSignetP2tr,
    BitcoinRegtestP2pkh,
    BitcoinRegtestP2sh,
    BitcoinRegtestP2wpkh,
    BitcoinRegtestP2wsh,
    BitcoinRegtestP2tr,
    Sei,
    Xlm,
    DogeMainnet,
    DogeTestnet,
    TonV3r2,
    TonV4r2,
    Xrp,
    TonV5r1,
}

impl From<AddressFormatArg> for AddressFormat {
    fn from(a: AddressFormatArg) -> Self {
        match a {
            AddressFormatArg::Uncompressed => AddressFormat::Uncompressed,
            AddressFormatArg::Compressed => AddressFormat::Compressed,
            AddressFormatArg::Ethereum => AddressFormat::Ethereum,
            AddressFormatArg::Solana => AddressFormat::Solana,
            AddressFormatArg::Cosmos => AddressFormat::Cosmos,
            AddressFormatArg::Tron => AddressFormat::Tron,
            AddressFormatArg::Sui => AddressFormat::Sui,
            AddressFormatArg::Aptos => AddressFormat::Aptos,
            AddressFormatArg::BitcoinMainnetP2pkh => AddressFormat::BitcoinMainnetP2pkh,
            AddressFormatArg::BitcoinMainnetP2sh => AddressFormat::BitcoinMainnetP2sh,
            AddressFormatArg::BitcoinMainnetP2wpkh => AddressFormat::BitcoinMainnetP2wpkh,
            AddressFormatArg::BitcoinMainnetP2wsh => AddressFormat::BitcoinMainnetP2wsh,
            AddressFormatArg::BitcoinMainnetP2tr => AddressFormat::BitcoinMainnetP2tr,
            AddressFormatArg::BitcoinTestnetP2pkh => AddressFormat::BitcoinTestnetP2pkh,
            AddressFormatArg::BitcoinTestnetP2sh => AddressFormat::BitcoinTestnetP2sh,
            AddressFormatArg::BitcoinTestnetP2wpkh => AddressFormat::BitcoinTestnetP2wpkh,
            AddressFormatArg::BitcoinTestnetP2wsh => AddressFormat::BitcoinTestnetP2wsh,
            AddressFormatArg::BitcoinTestnetP2tr => AddressFormat::BitcoinTestnetP2tr,
            AddressFormatArg::BitcoinSignetP2pkh => AddressFormat::BitcoinSignetP2pkh,
            AddressFormatArg::BitcoinSignetP2sh => AddressFormat::BitcoinSignetP2sh,
            AddressFormatArg::BitcoinSignetP2wpkh => AddressFormat::BitcoinSignetP2wpkh,
            AddressFormatArg::BitcoinSignetP2wsh => AddressFormat::BitcoinSignetP2wsh,
            AddressFormatArg::BitcoinSignetP2tr => AddressFormat::BitcoinSignetP2tr,
            AddressFormatArg::BitcoinRegtestP2pkh => AddressFormat::BitcoinRegtestP2pkh,
            AddressFormatArg::BitcoinRegtestP2sh => AddressFormat::BitcoinRegtestP2sh,
            AddressFormatArg::BitcoinRegtestP2wpkh => AddressFormat::BitcoinRegtestP2wpkh,
            AddressFormatArg::BitcoinRegtestP2wsh => AddressFormat::BitcoinRegtestP2wsh,
            AddressFormatArg::BitcoinRegtestP2tr => AddressFormat::BitcoinRegtestP2tr,
            AddressFormatArg::Sei => AddressFormat::Sei,
            AddressFormatArg::Xlm => AddressFormat::Xlm,
            AddressFormatArg::DogeMainnet => AddressFormat::DogeMainnet,
            AddressFormatArg::DogeTestnet => AddressFormat::DogeTestnet,
            AddressFormatArg::TonV3r2 => AddressFormat::TonV3r2,
            AddressFormatArg::TonV4r2 => AddressFormat::TonV4r2,
            AddressFormatArg::Xrp => AddressFormat::Xrp,
            AddressFormatArg::TonV5r1 => AddressFormat::TonV5r1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sdk_to_cli_address_format(format: AddressFormat) -> Option<AddressFormatArg> {
        match format {
            AddressFormat::Unspecified => None,
            AddressFormat::Uncompressed => Some(AddressFormatArg::Uncompressed),
            AddressFormat::Compressed => Some(AddressFormatArg::Compressed),
            AddressFormat::Ethereum => Some(AddressFormatArg::Ethereum),
            AddressFormat::Solana => Some(AddressFormatArg::Solana),
            AddressFormat::Cosmos => Some(AddressFormatArg::Cosmos),
            AddressFormat::Tron => Some(AddressFormatArg::Tron),
            AddressFormat::Sui => Some(AddressFormatArg::Sui),
            AddressFormat::Aptos => Some(AddressFormatArg::Aptos),
            AddressFormat::BitcoinMainnetP2pkh => Some(AddressFormatArg::BitcoinMainnetP2pkh),
            AddressFormat::BitcoinMainnetP2sh => Some(AddressFormatArg::BitcoinMainnetP2sh),
            AddressFormat::BitcoinMainnetP2wpkh => Some(AddressFormatArg::BitcoinMainnetP2wpkh),
            AddressFormat::BitcoinMainnetP2wsh => Some(AddressFormatArg::BitcoinMainnetP2wsh),
            AddressFormat::BitcoinMainnetP2tr => Some(AddressFormatArg::BitcoinMainnetP2tr),
            AddressFormat::BitcoinTestnetP2pkh => Some(AddressFormatArg::BitcoinTestnetP2pkh),
            AddressFormat::BitcoinTestnetP2sh => Some(AddressFormatArg::BitcoinTestnetP2sh),
            AddressFormat::BitcoinTestnetP2wpkh => Some(AddressFormatArg::BitcoinTestnetP2wpkh),
            AddressFormat::BitcoinTestnetP2wsh => Some(AddressFormatArg::BitcoinTestnetP2wsh),
            AddressFormat::BitcoinTestnetP2tr => Some(AddressFormatArg::BitcoinTestnetP2tr),
            AddressFormat::BitcoinSignetP2pkh => Some(AddressFormatArg::BitcoinSignetP2pkh),
            AddressFormat::BitcoinSignetP2sh => Some(AddressFormatArg::BitcoinSignetP2sh),
            AddressFormat::BitcoinSignetP2wpkh => Some(AddressFormatArg::BitcoinSignetP2wpkh),
            AddressFormat::BitcoinSignetP2wsh => Some(AddressFormatArg::BitcoinSignetP2wsh),
            AddressFormat::BitcoinSignetP2tr => Some(AddressFormatArg::BitcoinSignetP2tr),
            AddressFormat::BitcoinRegtestP2pkh => Some(AddressFormatArg::BitcoinRegtestP2pkh),
            AddressFormat::BitcoinRegtestP2sh => Some(AddressFormatArg::BitcoinRegtestP2sh),
            AddressFormat::BitcoinRegtestP2wpkh => Some(AddressFormatArg::BitcoinRegtestP2wpkh),
            AddressFormat::BitcoinRegtestP2wsh => Some(AddressFormatArg::BitcoinRegtestP2wsh),
            AddressFormat::BitcoinRegtestP2tr => Some(AddressFormatArg::BitcoinRegtestP2tr),
            AddressFormat::Sei => Some(AddressFormatArg::Sei),
            AddressFormat::Xlm => Some(AddressFormatArg::Xlm),
            AddressFormat::DogeMainnet => Some(AddressFormatArg::DogeMainnet),
            AddressFormat::DogeTestnet => Some(AddressFormatArg::DogeTestnet),
            AddressFormat::TonV3r2 => Some(AddressFormatArg::TonV3r2),
            AddressFormat::TonV4r2 => Some(AddressFormatArg::TonV4r2),
            AddressFormat::Xrp => Some(AddressFormatArg::Xrp),
            AddressFormat::TonV5r1 => Some(AddressFormatArg::TonV5r1),
        }
    }

    #[test]
    fn address_format_arg_roundtrips_for_all_cli_variants() {
        for cli_variant in AddressFormatArg::value_variants().iter().cloned() {
            let sdk_variant = AddressFormat::from(cli_variant.clone());
            let back_to_cli = sdk_to_cli_address_format(sdk_variant)
                .expect("CLI variant mapped to SDK Unspecified");
            assert_eq!(
                cli_variant
                    .to_possible_value()
                    .map(|v| v.get_name().to_string()),
                back_to_cli
                    .to_possible_value()
                    .map(|v| v.get_name().to_string())
            );
        }
    }
}

async fn create(args: CreateArgs) -> Result<()> {
    let config = turnkey_auth::config::Config::resolve().await?;
    let signer = turnkey_auth::turnkey::TurnkeySigner::new(config)?;
    let client = signer.client();
    let org_id = signer.organization_id().to_string();

    let curve: Curve = args.curve.into();
    let address_formats: Vec<AddressFormat> =
        args.address_formats.into_iter().map(Into::into).collect();

    let response = client
        .create_private_keys(
            org_id,
            client.current_timestamp(),
            activity::CreatePrivateKeysIntentV2 {
                private_keys: vec![activity::PrivateKeyParams {
                    private_key_name: args.name,
                    curve: curve.into(),
                    private_key_tags: args.tags,
                    address_formats: address_formats.into_iter().map(Into::into).collect(),
                }],
            },
        )
        .await
        .map_err(|e| anyhow!("failed to create private key: {e}"))?;

    let key_id = response
        .result
        .private_keys
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("Turnkey did not return the created private key"))?
        .private_key_id;

    println!("{}", serde_json::json!({ "privateKeyId": key_id }));
    Ok(())
}

async fn delete(args: DeleteArgs) -> Result<()> {
    let config = turnkey_auth::config::Config::resolve().await?;
    let signer = turnkey_auth::turnkey::TurnkeySigner::new(config)?;
    let client = signer.client();
    let org_id = signer.organization_id().to_string();

    client
        .delete_private_keys(
            org_id,
            client.current_timestamp(),
            activity::DeletePrivateKeysIntent {
                private_key_ids: args.key_ids.clone(),
                delete_without_export: Some(args.delete_without_export),
            },
        )
        .await
        .map_err(|e| anyhow!("failed to delete private keys: {e}"))?;

    println!("{}", serde_json::json!({ "deletedKeyIds": args.key_ids }));
    Ok(())
}
