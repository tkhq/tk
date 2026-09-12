//! OpenPGP keys held as Turnkey wallet accounts.
//!
//! One key is one account: a signing account under its own index, whose
//! name is the OpenPGP user ID. It is P-256 with an uncompressed address,
//! so the account address is the SEC1 point the key packet carries.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use tracing::debug;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_auth::openpgp::entity::{OpenPgpKey, UserId};
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

/// The BIP-32 purpose this feature reserves for OpenPGP keys. `5261136` is
/// `0x504750`, the ASCII of "PGP". The value is fixed: every key already
/// created derives from it, so changing it would orphan them all.
const PATH_NAMESPACE: u32 = 5261136;

/// How many accounts one page of the account listing asks for. The API caps
/// a page at 100.
const PAGE_SIZE: u32 = 100;

/// Returns the derivation path of the signing account of key `index`.
fn signing_path(index: u32) -> String {
    format!("m/{PATH_NAMESPACE}'/0'/{index}'/0'")
}

/// Reads a signing account's derivation path, returning its key index. Any
/// other path yields `None`, which is how a wallet's unrelated accounts are
/// skipped. A path under the namespace that is not a signing path is skipped
/// the same way: an older client made an encryption account at `/1'`, and
/// this feature no longer reads or writes one.
fn parse_path(path: &str) -> Option<u32> {
    let tail = path.strip_prefix(&format!("m/{PATH_NAMESPACE}'/0'/"))?;
    let index = tail.strip_suffix("'/0'")?;
    index.parse().ok()
}

/// One wallet account that holds an OpenPGP key.
pub struct GpgKey {
    /// The key index, which is the third element of the derivation path.
    pub index: u32,
    /// The OpenPGP identity the account carries.
    pub key: OpenPgpKey,
}

impl From<GpgKey> for KeySummary {
    fn from(key: GpgKey) -> Self {
        let GpgKey { index, key } = key;
        Self {
            key_index: index,
            fingerprint: key.fingerprint_hex(),
            user_id: key.user_id.into_string(),
            created: key.created,
        }
    }
}

/// Everything one pass over a wallet's accounts yields.
pub struct WalletKeys {
    /// The usable keys, sorted by index.
    pub keys: Vec<GpgKey>,
    /// Every key index that already holds a signing account, whether or not
    /// that account is usable. A create at an occupied index would ask for a
    /// derivation path the wallet already has.
    pub occupied: BTreeSet<u32>,
}

/// Reads every account in the wallet, one page at a time.
async fn wallet_accounts(
    client: &TurnkeyClient<TurnkeyP256ApiKey>,
    org_id: &str,
    wallet_id: Uuid,
) -> Result<Vec<WalletAccount>> {
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
            _ => return Ok(accounts),
        }
    }
}

/// Parses `created_at.seconds` off one account. The key packet carries that
/// stamp, so the fingerprint depends on it. The value is a stringified
/// integer on the wire, so a missing or non numeric one is a malformed API
/// value rather than an absent field.
fn created_seconds(account_id: &str, created_at: Option<&str>) -> Result<u32> {
    let seconds = created_at.ok_or_else(|| {
        ActivityError::new(
            ActivityErrorKind::MalformedResponse,
            format!("get_wallet_accounts returned account {account_id} without created_at.seconds"),
        )
    })?;
    seconds.parse().map_err(|error| {
        ActivityError::new(
            ActivityErrorKind::MalformedResponse,
            format!(
                "get_wallet_accounts returned account {account_id} with a non numeric created_at.seconds"
            ),
        )
        .with_source(error)
        .into()
    })
}

/// Sorts a wallet's accounts into keys and the set of indexes its signing
/// accounts occupy.
///
/// Only a P-256 account with an uncompressed address can carry an OpenPGP
/// point, so any other signing account under the namespace is skipped rather
/// than reported as malformed: it is a legal wallet account that this
/// feature did not make, and one of them must not block every gpg command on
/// the wallet. It still occupies its index. An unnamed account, and one
/// whose name is not a usable user ID, are skipped the same way.
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
        // The address came from the API and the account claims to be P-256
        // uncompressed, so a point that will not parse is a malformed API
        // value rather than bad input from the caller.
        let signing_point = parse_point_hex(&address).map_err(|error| {
            ActivityError::new(
                ActivityErrorKind::MalformedResponse,
                format!(
                    "get_wallet_accounts returned account {wallet_account_id} with an address that is not a P-256 point"
                ),
            )
            .with_source(error)
        })?;
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
        let created = created_seconds(
            &wallet_account_id,
            created_at.as_ref().map(|stamp| stamp.seconds.as_str()),
        )?;
        keys.insert(
            index,
            GpgKey {
                index,
                key: OpenPgpKey {
                    user_id,
                    signing_point,
                    created,
                },
            },
        );
    }

    Ok(WalletKeys {
        keys: keys.into_values().collect(),
        occupied,
    })
}

/// Reads the wallet once and returns both its keys and the indexes its
/// signing accounts occupy.
pub async fn read_wallet(
    client: &TurnkeyClient<TurnkeyP256ApiKey>,
    org_id: &str,
    wallet_id: Uuid,
) -> Result<WalletKeys> {
    sort_accounts(wallet_accounts(client, org_id, wallet_id).await?)
}

/// Lists every key in the wallet, sorted by index, for callers that do not
/// need the occupied indexes.
pub async fn list_keys(
    client: &TurnkeyClient<TurnkeyP256ApiKey>,
    org_id: &str,
    wallet_id: Uuid,
) -> Result<Vec<GpgKey>> {
    Ok(read_wallet(client, org_id, wallet_id).await?.keys)
}

/// Creates the signing account at `index`, then reads the wallet back to
/// learn the account's creation time, which the fingerprint depends on.
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

    list_keys(client, org_id, wallet_id)
        .await?
        .into_iter()
        .find(|key| key.index == index)
        .ok_or_else(|| MissingResource::new("OpenPGP key", index.to_string()).into())
}

/// Why a key selection found no single key. Each message states the fact
/// alone. The remediation depends on what levers the caller's user has, so
/// the command layer words it, not this helper.
#[derive(Debug, thiserror::Error)]
pub enum SelectError {
    /// The wallet holds no OpenPGP key at all.
    #[error("wallet {wallet_id} holds no OpenPGP keys")]
    NoKeys { wallet_id: Uuid },
    /// The wallet holds more than one key and the caller named none.
    #[error("wallet {wallet_id} holds {count} OpenPGP keys and none was named")]
    Ambiguous { wallet_id: Uuid, count: usize },
    /// The wallet holds no key at the index the caller named.
    #[error("wallet {wallet_id} holds no OpenPGP key at index {index}")]
    Missing { wallet_id: Uuid, index: u32 },
}

/// Picks the key at `index`, or the only key when `index` is `None`.
pub fn select(
    keys: Vec<GpgKey>,
    wallet_id: Uuid,
    index: Option<u32>,
) -> Result<GpgKey, SelectError> {
    let Some(index) = index else {
        let count = keys.len();
        let mut keys = keys.into_iter();
        let Some(only) = keys.next() else {
            return Err(SelectError::NoKeys { wallet_id });
        };
        if keys.next().is_some() {
            return Err(SelectError::Ambiguous { wallet_id, count });
        }
        return Ok(only);
    };
    keys.into_iter()
        .find(|key| key.index == index)
        .ok_or(SelectError::Missing { wallet_id, index })
}

/// The lowest index no signing account already occupies.
pub fn next_free_index(occupied: &BTreeSet<u32>) -> u32 {
    let mut next = 0;
    for index in occupied {
        match (*index).cmp(&next) {
            Ordering::Equal => next += 1,
            Ordering::Greater => break,
            Ordering::Less => {}
        }
    }
    next
}

#[cfg(test)]
mod tests {
    use turnkey_client::generated::external::data::v1::Timestamp;

    use super::*;

    /// The NIST P-256 generator point G, uncompressed, standing in for any
    /// account address this feature would accept.
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

    fn encryption_path(index: u32) -> String {
        format!("m/{PATH_NAMESPACE}'/0'/{index}'/1'")
    }

    fn key(index: u32, user_id: &str) -> Vec<WalletAccount> {
        vec![account(signing_path(index), Some(user_id))]
    }

    fn sorted(accounts: Vec<WalletAccount>) -> WalletKeys {
        sort_accounts(accounts).expect("well formed accounts should sort")
    }

    #[test]
    fn a_signing_account_becomes_one_key_and_occupies_its_index() {
        let WalletKeys { keys, occupied } = sorted(key(0, "Ada <ada@example.com>"));
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].index, 0);
        assert_eq!(keys[0].key.user_id.as_str(), "Ada <ada@example.com>");
        assert_eq!(keys[0].key.created, 1_700_000_000);
        assert_eq!(occupied, BTreeSet::from([0]));
    }

    /// An older client made an encryption account at `/1'`. This feature
    /// no longer reads one, so it yields no key and occupies no index.
    #[test]
    fn an_encryption_account_from_an_older_client_is_ignored() {
        let WalletKeys { keys, occupied } = sorted(vec![account(encryption_path(0), None)]);
        assert!(keys.is_empty());
        assert_eq!(occupied, BTreeSet::new());
        assert_eq!(next_free_index(&occupied), 0);
    }

    #[test]
    fn an_unnamed_signing_account_still_occupies_its_index() {
        let WalletKeys { keys, occupied } = sorted(vec![account(signing_path(0), None)]);
        assert!(keys.is_empty());
        assert_eq!(occupied, BTreeSet::from([0]));
        assert_eq!(next_free_index(&occupied), 1);
    }

    #[test]
    fn a_namespace_account_on_another_curve_is_skipped_without_failing() {
        let mut accounts = key(0, "Ada <ada@example.com>");
        for account in &mut accounts {
            account.curve = Curve::Secp256k1;
            account.address_format = AddressFormat::Ethereum;
            account.address = "0x000000000000000000000000000000000000dead".to_string();
        }
        accounts.extend(key(1, "Grace <grace@example.com>"));

        let WalletKeys { keys, occupied } = sorted(accounts);
        assert_eq!(keys.len(), 1, "the P-256 account is still usable");
        assert_eq!(keys[0].index, 1);
        assert_eq!(occupied, BTreeSet::from([0, 1]));
        assert_eq!(next_free_index(&occupied), 2);
    }

    #[test]
    fn accounts_outside_the_namespace_are_ignored() {
        let mut accounts = vec![account("m/44'/60'/0'/0/0".to_string(), Some("eth"))];
        accounts.extend(key(3, "Ada <ada@example.com>"));

        let WalletKeys { keys, occupied } = sorted(accounts);
        assert_eq!(keys.len(), 1);
        assert_eq!(occupied, BTreeSet::from([3]));
        assert_eq!(next_free_index(&occupied), 0);
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
    fn a_missing_created_at_is_a_malformed_response_naming_the_field() {
        let error = created_seconds("account-1", None).expect_err("a missing stamp should fail");
        let activity = error
            .downcast_ref::<ActivityError>()
            .expect("the error should be an ActivityError");
        assert_eq!(activity.kind(), ActivityErrorKind::MalformedResponse);
        assert_eq!(
            activity.to_string(),
            "get_wallet_accounts returned account account-1 without created_at.seconds"
        );
    }

    #[test]
    fn a_non_numeric_created_at_is_a_malformed_response_naming_the_field() {
        let error =
            created_seconds("account-1", Some("later")).expect_err("a bad stamp should fail");
        let activity = error
            .downcast_ref::<ActivityError>()
            .expect("the error should be an ActivityError");
        assert_eq!(activity.kind(), ActivityErrorKind::MalformedResponse);
        assert_eq!(
            activity.to_string(),
            "get_wallet_accounts returned account account-1 with a non numeric created_at.seconds"
        );
        assert_eq!(
            error.chain().count(),
            2,
            "the parse failure stays in the chain"
        );
    }

    #[test]
    fn a_signing_path_carries_the_namespace_and_the_index() {
        assert_eq!(signing_path(3), "m/5261136'/0'/3'/0'");
    }

    #[test]
    fn parse_path_round_trips_a_signing_path() {
        assert_eq!(parse_path(&signing_path(0)), Some(0));
        assert_eq!(parse_path(&signing_path(7)), Some(7));
    }

    #[test]
    fn parse_path_rejects_every_other_path() {
        for path in [
            "m/44'/60'/0'/0/0",
            "m/5261136'/0'/0'/1'",
            "m/5261136'/0'/0'/2'",
            "m/5261136'/1'/0'/0'",
            "m/5261136'/0'/x'/0'",
            "m/5261136'/0'/0'/0",
        ] {
            assert_eq!(parse_path(path), None, "{path} should not parse");
        }
    }
}
