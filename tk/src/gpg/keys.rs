//! OpenPGP keys held as Turnkey wallet accounts: one P-256 account with an
//! uncompressed address per key index, named with the OpenPGP user ID.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use tracing::debug;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_auth::openpgp::entity::{OpenPgpKey, SigningKey, UserId};
use turnkey_auth::openpgp::key::parse_point_hex;
use turnkey_client::TurnkeyClient;
use turnkey_client::generated::{
    CreateWalletAccountsIntent, GetWalletAccountsRequest, GetWalletAccountsResponse,
    WalletAccountParams,
    external::{data::v1::WalletAccount, options::v1::Pagination},
    immutable::common::v1::{AddressFormat, Curve, PathFormat},
};
use uuid::Uuid;

use crate::errors::{ActivityError, ActivityErrorKind, MissingResource};
use crate::gpg::KeySummary;
use crate::gpg::registry::SigningKeyName;

/// The BIP-32 purpose reserved for OpenPGP keys: `0x504750`, ASCII "PGP".
/// Changing it would orphan every key already created.
const PATH_NAMESPACE: u32 = 5261136;

/// The API caps a page at 100.
const PAGE_SIZE: u32 = 100;

fn signing_path(index: u32) -> String {
    format!("m/{PATH_NAMESPACE}'/0'/{index}'/0'")
}

/// The key index of a signing account's path; `None` for any other path.
fn parse_path(path: &str) -> Option<u32> {
    let tail = path.strip_prefix(&format!("m/{PATH_NAMESPACE}'/0'/"))?;
    tail.strip_suffix("'/0'")?.parse().ok()
}

pub struct GpgKey {
    pub index: u32,
    pub account_id: String,
    pub key: OpenPgpKey,
}

impl From<GpgKey> for KeySummary {
    fn from(key: GpgKey) -> Self {
        let GpgKey {
            index,
            account_id: _,
            key,
        } = key;
        Self {
            key_index: index,
            fingerprint: key.signing.fingerprint_hex(),
            user_id: key.user_id.into_string(),
            created: key.signing.created,
        }
    }
}

pub struct WalletKeys {
    /// Usable keys, sorted by index.
    pub keys: Vec<GpgKey>,
    /// Every index holding a signing account, usable or not.
    pub occupied: BTreeSet<u32>,
}

pub async fn read_wallet(
    client: &TurnkeyClient<TurnkeyP256ApiKey>,
    org_id: &str,
    wallet_id: Uuid,
) -> Result<WalletKeys> {
    let mut accounts = Vec::new();
    let mut after = String::new();
    loop {
        let GetWalletAccountsResponse { accounts: page } = client
            .get_wallet_accounts(GetWalletAccountsRequest {
                organization_id: org_id.to_string(),
                wallet_id: Some(wallet_id.to_string()),
                include_wallet_details: None,
                pagination_options: Some(Pagination {
                    limit: PAGE_SIZE.to_string(),
                    before: String::new(),
                    after: after.clone(),
                }),
            })
            .await
            .map_err(anyhow::Error::new)
            .with_context(|| format!("list accounts of wallet {wallet_id}"))?;
        let full = page.len() == PAGE_SIZE as usize;
        let last = page.last().map(|account| account.wallet_account_id.clone());
        accounts.extend(page);
        match last {
            // A cursor that does not move would page over the same accounts
            // for ever, so it is reported rather than followed.
            Some(last) if full && last == after => {
                return Err(ActivityError::new(
                    ActivityErrorKind::MalformedResponse,
                    format!(
                        "get_wallet_accounts returned a full page of wallet {wallet_id} without advancing its cursor"
                    ),
                )
                .into());
            }
            Some(last) if full => after = last,
            _ => return sort_accounts(accounts),
        }
    }
}

/// A signing account this feature could not have made (wrong curve or
/// address format, unnamed, or not named with a user ID) is skipped rather
/// than reported, but still occupies its index.
fn sort_accounts(accounts: Vec<WalletAccount>) -> Result<WalletKeys> {
    let mut occupied = BTreeSet::new();
    let mut keys: BTreeMap<u32, GpgKey> = BTreeMap::new();

    for account in accounts {
        let WalletAccount {
            wallet_account_id,
            organization_id: _,
            wallet_id: _,
            curve,
            path_format: _,
            path,
            address_format,
            address,
            created_at,
            updated_at: _,
            public_key: _,
            wallet_details: _,
            name,
            caip2_prefix: _,
        } = account;

        let Some(index) = parse_path(&path) else {
            continue;
        };
        occupied.insert(index);

        if curve != Curve::P256 || address_format != AddressFormat::Uncompressed {
            debug!(
                %wallet_account_id,
                %path,
                "skipping a namespace account that is not P-256 uncompressed"
            );
            continue;
        }
        let Some(name) = name else {
            debug!(%wallet_account_id, "skipping an unnamed OpenPGP signing account");
            continue;
        };
        let Ok(user_id) = UserId::parse(name) else {
            debug!(
                %wallet_account_id,
                "skipping an OpenPGP signing account whose name is not a user ID"
            );
            continue;
        };
        // The account claims to be P-256 uncompressed and `created_at.seconds`
        // is a stringified integer on the wire, so a value that will not
        // parse is a malformed API value rather than bad input or absence.
        let malformed = |reason: &str| {
            ActivityError::new(
                ActivityErrorKind::MalformedResponse,
                format!("get_wallet_accounts returned account {wallet_account_id} {reason}"),
            )
        };
        let point = parse_point_hex(&address).map_err(|error| {
            malformed("with an address that is not a P-256 point").with_source(error)
        })?;
        let created: u32 = created_at
            .ok_or_else(|| malformed("without created_at.seconds"))?
            .seconds
            .parse()
            .map_err(|error| {
                malformed("with a non numeric created_at.seconds").with_source(error)
            })?;
        keys.insert(
            index,
            GpgKey {
                index,
                account_id: wallet_account_id,
                key: OpenPgpKey {
                    user_id,
                    signing: SigningKey { point, created },
                },
            },
        );
    }

    Ok(WalletKeys {
        keys: keys.into_values().collect(),
        occupied,
    })
}

/// Creates the signing account, then reads the wallet back for the creation
/// time the fingerprint depends on.
pub async fn create_key(
    client: &TurnkeyClient<TurnkeyP256ApiKey>,
    org_id: &str,
    wallet_id: Uuid,
    index: u32,
    user_id: UserId,
) -> Result<GpgKey> {
    client
        .create_wallet_accounts(
            org_id.to_string(),
            client.current_timestamp(),
            CreateWalletAccountsIntent {
                wallet_id: wallet_id.to_string(),
                accounts: vec![WalletAccountParams {
                    curve: Curve::P256,
                    path_format: PathFormat::Bip32,
                    path: signing_path(index),
                    address_format: AddressFormat::Uncompressed,
                    name: Some(user_id.into_string()),
                }],
                persist: None,
            },
        )
        .await
        .map_err(anyhow::Error::new)
        .with_context(|| format!("create OpenPGP key {index} in wallet {wallet_id}"))?;

    read_wallet(client, org_id, wallet_id)
        .await?
        .keys
        .into_iter()
        .find(|key| key.index == index)
        .ok_or_else(|| MissingResource::new("OpenPGP key", index.to_string()).into())
}

/// States the fact alone; the command layer adds the remediation.
#[derive(Debug, thiserror::Error)]
pub enum SelectError {
    #[error("wallet {wallet_id} holds no OpenPGP keys")]
    NoKeys { wallet_id: Uuid },
    #[error("wallet {wallet_id} holds {count} OpenPGP keys and none was named")]
    Ambiguous { wallet_id: Uuid, count: usize },
    #[error("no OpenPGP key in wallet {wallet_id} matches signing key {name}")]
    NoMatch {
        wallet_id: Uuid,
        name: SigningKeyName,
    },
    #[error(
        "signing key {name} matches several OpenPGP keys in wallet {wallet_id}; use a longer fingerprint"
    )]
    SeveralMatch {
        wallet_id: Uuid,
        name: SigningKeyName,
    },
}

pub fn select(
    keys: Vec<GpgKey>,
    wallet_id: Uuid,
    name: Option<&SigningKeyName>,
) -> Result<GpgKey, SelectError> {
    let Some(name) = name else {
        return match keys.len() {
            0 => Err(SelectError::NoKeys { wallet_id }),
            1 => Ok(keys.into_iter().next().expect("one key")),
            count => Err(SelectError::Ambiguous { wallet_id, count }),
        };
    };
    let suffix = name.to_string();
    let mut matching = keys
        .into_iter()
        .filter(|key| key.key.signing.fingerprint_hex().ends_with(&suffix));
    let Some(key) = matching.next() else {
        return Err(SelectError::NoMatch {
            wallet_id,
            name: name.clone(),
        });
    };
    if matching.next().is_some() {
        return Err(SelectError::SeveralMatch {
            wallet_id,
            name: name.clone(),
        });
    }
    Ok(key)
}

pub fn next_free_index(occupied: &BTreeSet<u32>) -> u32 {
    (0..)
        .find(|index| !occupied.contains(index))
        .expect("u32 has a free index")
}

#[cfg(test)]
mod tests {
    use turnkey_client::generated::external::data::v1::Timestamp;

    use super::*;

    const POINT: &str = concat!(
        "04",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
    );

    fn account(path: String, name: Option<&str>) -> WalletAccount {
        WalletAccount {
            wallet_account_id: format!("account-at-{path}"),
            organization_id: String::new(),
            wallet_id: String::new(),
            curve: Curve::P256,
            path_format: PathFormat::Bip32,
            path,
            address_format: AddressFormat::Uncompressed,
            address: POINT.to_string(),
            created_at: Some(Timestamp {
                seconds: "1700000000".to_string(),
                nanos: "0".to_string(),
            }),
            updated_at: None,
            public_key: None,
            wallet_details: None,
            name: name.map(str::to_string),
            caip2_prefix: None,
        }
    }

    fn key(index: u32, user_id: &str) -> Vec<WalletAccount> {
        vec![account(signing_path(index), Some(user_id))]
    }

    #[test]
    fn a_bad_p256_address_is_a_malformed_response_naming_the_account() {
        let mut accounts = key(0, "Ada <ada@example.com>");
        accounts[0].address = "not-a-point".to_string();

        let Err(error) = sort_accounts(accounts) else {
            panic!("a bad P-256 address should fail")
        };
        let activity = error
            .downcast_ref::<ActivityError>()
            .expect("the error should be an ActivityError");
        assert_eq!(activity.kind(), ActivityErrorKind::MalformedResponse);
        assert_eq!(
            activity.to_string(),
            "get_wallet_accounts returned account account-at-m/5261136'/0'/0'/0' with an address that is not a P-256 point"
        );
        // The cause is kept in the chain instead of being folded into the
        // message above.
        assert_eq!(
            error.chain().nth(1).map(ToString::to_string).as_deref(),
            Some("expected a hex encoded public key")
        );
    }

    #[test]
    fn a_missing_or_non_numeric_created_at_is_a_malformed_response_naming_the_field() {
        for (stamp, message, chain_len) in [
            (
                None,
                "get_wallet_accounts returned account account-at-m/5261136'/0'/0'/0' without created_at.seconds",
                1,
            ),
            (
                Some("later"),
                "get_wallet_accounts returned account account-at-m/5261136'/0'/0'/0' with a non numeric created_at.seconds",
                2,
            ),
        ] {
            let mut accounts = key(0, "Ada <ada@example.com>");
            accounts[0].created_at = stamp.map(|seconds: &str| Timestamp {
                seconds: seconds.to_string(),
                nanos: "0".to_string(),
            });
            let Err(error) = sort_accounts(accounts) else {
                panic!("a bad stamp should fail")
            };
            let activity = error
                .downcast_ref::<ActivityError>()
                .expect("the error should be an ActivityError");
            assert_eq!(activity.kind(), ActivityErrorKind::MalformedResponse);
            assert_eq!(activity.to_string(), message);
            assert_eq!(
                error.chain().count(),
                chain_len,
                "the cause stays in the chain"
            );
        }
    }

    #[test]
    fn parse_path_rejects_every_other_path() {
        for path in [
            "m/44'/60'/0'/0/0",
            "m/5261136'/0'/0'/2'",
            "m/5261136'/1'/0'/0'",
            "m/5261136'/0'/x'/0'",
            "m/5261136'/0'/0'/0",
        ] {
            assert_eq!(parse_path(path), None, "{path} should not parse");
        }
    }
}
