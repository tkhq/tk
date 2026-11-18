//! Kebab-case command-line values for the API's enums.

use std::sync::LazyLock;

use clap::builder::{PossibleValuesParser, TypedValueParser};
use turnkey_client::generated::immutable::common::v1::{
    AddressFormat, Curve, HashFunction, PathFormat, PayloadEncoding, TransactionType,
};

/// An API enum with a fixed list of specified variants, excluding `Unspecified`.
pub trait ApiEnum: Copy + Send + Sync + 'static {
    /// Prefix every API name shares, removed to build the command-line name.
    const PREFIX: &'static str;
    /// Every specified variant.
    const ALL: &'static [Self];
    /// The API's name for the variant, such as `ADDRESS_FORMAT_ETHEREUM`.
    fn api_name(self) -> &'static str;
    /// Every specified variant with its command-line name, built once.
    fn names() -> &'static [(&'static str, Self)];

    /// The command-line name, such as `ethereum` or `bitcoin-mainnet-p2pkh`.
    fn cli_name(self) -> String {
        let name = self.api_name();
        name.strip_prefix(Self::PREFIX)
            .unwrap_or(name)
            .to_ascii_lowercase()
            .replace('_', "-")
    }

    /// The variant with this command-line name.
    fn lookup(name: &str) -> Option<Self> {
        Self::names()
            .iter()
            .find_map(|&(candidate, variant)| (candidate == name).then_some(variant))
    }
}

macro_rules! api_enum {
    ($type:ident, $prefix:literal, [$($variant:ident),+ $(,)?]) => {
        // Fails to compile when the API adds a variant that the list omits.
        const _: fn($type) = |variant| match variant {
            $type::Unspecified => {}
            $($type::$variant)|+ => {}
        };

        impl ApiEnum for $type {
            const PREFIX: &'static str = $prefix;
            const ALL: &'static [Self] = &[$(Self::$variant),+];
            fn api_name(self) -> &'static str {
                self.as_str_name()
            }
            fn names() -> &'static [(&'static str, Self)] {
                // Clap's possible values borrow the names for the whole process.
                static NAMES: LazyLock<Vec<(&'static str, $type)>> = LazyLock::new(|| {
                    $type::ALL
                        .iter()
                        .map(|&variant| {
                            let name: &'static str =
                                Box::leak(variant.cli_name().into_boxed_str());
                            (name, variant)
                        })
                        .collect()
                });
                &NAMES
            }
        }
    };
}

api_enum!(
    AddressFormat,
    "ADDRESS_FORMAT_",
    [
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
        TonV5r1,
        Xrp,
        SparkMainnet,
        SparkRegtest,
    ]
);
api_enum!(Curve, "CURVE_", [Secp256k1, Ed25519, P256]);
api_enum!(PathFormat, "PATH_FORMAT_", [Bip32]);
api_enum!(
    PayloadEncoding,
    "PAYLOAD_ENCODING_",
    [Hexadecimal, TextUtf8, Eip712, Eip7702Authorization]
);
api_enum!(
    HashFunction,
    "HASH_FUNCTION_",
    [NoOp, Sha256, Keccak256, NotApplicable]
);
api_enum!(
    TransactionType,
    "TRANSACTION_TYPE_",
    [Ethereum, Solana, Tron, Bitcoin, Tempo]
);

/// Parses the kebab-case names of `T` and lists them in `--help`.
pub fn parser<T: ApiEnum>() -> impl TypedValueParser<Value = T> {
    PossibleValuesParser::new(T::names().iter().map(|&(name, _)| name))
        .try_map(|name| T::lookup(&name).ok_or("not a listed value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_unique_names<T: ApiEnum>() {
        let mut names: Vec<String> = T::ALL.iter().map(|&variant| variant.cli_name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), T::ALL.len(), "{}", T::PREFIX);
    }

    #[test]
    fn names_are_unique_and_resolve_without_the_prefix() {
        assert_unique_names::<AddressFormat>();
        assert_unique_names::<Curve>();
        assert_unique_names::<PathFormat>();
        assert_unique_names::<PayloadEncoding>();
        assert_unique_names::<HashFunction>();
        assert_unique_names::<TransactionType>();
        assert_eq!(
            AddressFormat::lookup("ton-v3r2"),
            Some(AddressFormat::TonV3r2)
        );
        assert_eq!(AddressFormat::lookup("ADDRESS_FORMAT_ETHEREUM"), None);
        assert_eq!(AddressFormat::lookup("Ethereum"), None);
        assert_eq!(AddressFormat::lookup("unspecified"), None);
    }
}
