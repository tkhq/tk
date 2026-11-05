use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    str::FromStr,
    sync::LazyLock,
};

use anyhow::{Result, bail};
use clap::{ArgGroup, Args, Subcommand};
use serde::Deserialize;
use serde_json::{json, to_value};
use turnkey_client::generated::{
    GetWalletAccountsRequest, GetWalletAccountsResponse, GetWalletRequest, GetWalletsRequest,
    external::options::v1::Pagination,
    immutable::{
        activity::v1::{
            CreateWalletAccountsIntent, CreateWalletIntent, SignRawPayloadIntentV2,
            SignTransactionIntentV2, UpdateWalletIntent, WalletAccountParams,
        },
        common::v1::{
            AddressFormat, Curve, HashFunction, PathFormat, PayloadEncoding, TransactionType,
        },
    },
};
use uuid::Uuid;

use crate::{
    auth::{ResolvedAuth, build_turnkey_client},
    enum_args::{self, ApiEnum},
    errors::{InvalidInput, Malformed, MissingResource},
    operations::{OperationOutput, query, submit_activity},
    resources::{BodyArgs, BodySource, read_input},
};

const ACCOUNT_PAGE_SIZE: u32 = 100;

fn parse_mnemonic_length(value: &str) -> Result<i32, String> {
    match value.parse() {
        Ok(words @ (12 | 15 | 18 | 21 | 24)) => Ok(words),
        _ => Err("must be 12, 15, 18, 21, or 24".into()),
    }
}

fn inferred_curve(address_format: AddressFormat) -> Option<Curve> {
    match address_format {
        AddressFormat::Ethereum | AddressFormat::Cosmos | AddressFormat::Uncompressed => {
            Some(Curve::Secp256k1)
        }
        AddressFormat::Solana => Some(Curve::Ed25519),
        _ => None,
    }
}

static NEEDS_CURVE: LazyLock<Vec<(&'static str, &'static str)>> = LazyLock::new(|| {
    AddressFormat::names()
        .iter()
        .filter(|&&(_, address_format)| inferred_curve(address_format).is_none())
        .map(|&(name, _)| ("address_format", name))
        .collect()
});

static NEEDS_PATH: LazyLock<Vec<(&'static str, &'static str)>> = LazyLock::new(|| {
    AddressFormat::names()
        .iter()
        .filter(|&&(_, address_format)| StandardFormat::of(address_format).is_none())
        .map(|&(name, _)| ("address_format", name))
        .collect()
});

/// One page of accounts, decoded loosely so an address format newer than this
/// client does not fail path prediction.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountPage {
    #[serde(default)]
    accounts: Vec<PredictedAccount>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PredictedAccount {
    wallet_account_id: String,
    path: String,
    address_format: String,
}

/// An address format with a conventional BIP-32 account path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StandardFormat {
    Ethereum,
    Cosmos,
    Solana,
    Uncompressed,
    Compressed,
}

impl StandardFormat {
    fn path(self, index: usize) -> String {
        match self {
            Self::Ethereum => format!("m/44'/60'/{index}'/0/0"),
            Self::Cosmos => format!("m/44'/118'/{index}'/0/0"),
            Self::Solana => format!("m/44'/501'/{index}'/0'"),
            Self::Uncompressed | Self::Compressed => format!("m/{index}'"),
        }
    }

    fn next_path(self, taken: &HashSet<String>) -> String {
        let mut index = 0;
        loop {
            let path = self.path(index);
            if !taken.contains(&path) {
                return path;
            }
            index += 1;
        }
    }

    fn of(address_format: AddressFormat) -> Option<Self> {
        match address_format {
            AddressFormat::Ethereum => Some(Self::Ethereum),
            AddressFormat::Cosmos => Some(Self::Cosmos),
            AddressFormat::Solana => Some(Self::Solana),
            AddressFormat::Uncompressed => Some(Self::Uncompressed),
            AddressFormat::Compressed => Some(Self::Compressed),
            _ => None,
        }
    }
}

impl From<StandardFormat> for AddressFormat {
    fn from(standard: StandardFormat) -> Self {
        match standard {
            StandardFormat::Ethereum => Self::Ethereum,
            StandardFormat::Cosmos => Self::Cosmos,
            StandardFormat::Solana => Self::Solana,
            StandardFormat::Uncompressed => Self::Uncompressed,
            StandardFormat::Compressed => Self::Compressed,
        }
    }
}

/// An account to create with a new wallet, written `ADDRESS_FORMAT[:PATH]`.
#[derive(Clone, Debug)]
pub struct AccountSpec {
    curve: Curve,
    target: AccountTarget,
}

#[derive(Clone, Debug)]
enum AccountTarget {
    Path {
        address_format: AddressFormat,
        path: String,
    },
    Next(StandardFormat),
}

impl FromStr for AccountSpec {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, String> {
        let (format, path) = match value.split_once(':') {
            Some((format, path)) if !path.is_empty() => (format, Some(path.to_owned())),
            Some(_) => return Err("the path after `:` must not be empty".into()),
            None => (value, None),
        };
        let address_format = AddressFormat::lookup(format)
            .ok_or_else(|| format!("unknown address format `{format}`, such as ethereum"))?;
        let curve = inferred_curve(address_format).ok_or_else(|| {
            format!("cannot infer the curve for {format}; use --input-json to name it")
        })?;
        let target = match path {
            Some(path) => AccountTarget::Path {
                address_format,
                path,
            },
            None => AccountTarget::Next(StandardFormat::of(address_format).ok_or_else(|| {
                format!("{format} has no conventional derivation path; write {format}:PATH")
            })?),
        };
        Ok(Self { curve, target })
    }
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("wallet_source").required(true).args(["input_json", "input_file", "name"])))]
#[command(group(ArgGroup::new("wallet_flags").multiple(true).args(["name", "accounts", "mnemonic_length"]).conflicts_with_all(["input_json", "input_file"])))]
pub struct CreateWalletArgs {
    #[command(flatten)]
    body: BodySource,
    /// Name of the new wallet.
    #[arg(long)]
    name: Option<String>,
    /// Account to create with the wallet; without a path, the next unused
    /// conventional path for the address format is used.
    ///
    /// The curve is inferred from the address format, so formats with no
    /// inferred curve need `--input-json`. Without this flag the wallet has no
    /// accounts.
    #[arg(
        long = "account",
        value_name = "ADDRESS_FORMAT[:PATH]",
        requires = "name"
    )]
    accounts: Vec<AccountSpec>,
    /// Number of words in the generated mnemonic.
    #[arg(long, requires = "name", value_parser = parse_mnemonic_length)]
    mnemonic_length: Option<i32>,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("account_source").required(true).args(["input_json", "input_file", "wallet_id"])))]
#[command(group(ArgGroup::new("account_flags").multiple(true).args(["wallet_id", "address_format", "curve", "path_format", "path"]).conflicts_with_all(["input_json", "input_file"])))]
pub struct CreateAccountArgs {
    #[command(flatten)]
    body: BodySource,
    /// Wallet to add the account to.
    #[arg(long, requires = "address_format")]
    wallet_id: Option<Uuid>,
    /// Address format of the account.
    #[arg(long, requires = "wallet_id", value_parser = enum_args::parser::<AddressFormat>())]
    address_format: Option<AddressFormat>,
    /// Curve of the account; inferred from the address format when omitted.
    #[arg(long, requires = "wallet_id", required_if_eq_any = NEEDS_CURVE.iter().copied(), value_parser = enum_args::parser::<Curve>())]
    curve: Option<Curve>,
    /// Derivation path format.
    #[arg(long, requires = "wallet_id", value_parser = enum_args::parser::<PathFormat>(), default_value = "bip32")]
    path_format: PathFormat,
    /// Derivation path; the next unused conventional path is used when omitted.
    #[arg(long, requires = "wallet_id", required_if_eq_any = NEEDS_PATH.iter().copied())]
    path: Option<String>,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("sign_payload_source").required(true).args(["input_json", "input_file", "sign_with"])))]
#[command(group(ArgGroup::new("payload_input").args(["payload", "payload_file"])))]
#[command(group(ArgGroup::new("sign_payload_flags").multiple(true).args(["sign_with", "payload", "payload_file", "encoding", "hash_function"]).conflicts_with_all(["input_json", "input_file"])))]
pub struct SignPayloadArgs {
    #[command(flatten)]
    body: BodySource,
    /// Wallet account address or private key ID that signs.
    #[arg(long, requires_all = ["payload_input", "encoding", "hash_function"])]
    sign_with: Option<String>,
    /// Payload to sign, in the given encoding.
    #[arg(long, requires = "sign_with")]
    payload: Option<String>,
    /// Read the payload from a file, or - for stdin.
    ///
    /// One trailing newline is removed; any other whitespace is signed.
    #[arg(long, requires = "sign_with")]
    payload_file: Option<PathBuf>,
    /// How the payload is encoded.
    #[arg(long, requires = "sign_with", value_parser = enum_args::parser::<PayloadEncoding>())]
    encoding: Option<PayloadEncoding>,
    /// Hash function applied to the payload before signing.
    #[arg(long, requires = "sign_with", value_parser = enum_args::parser::<HashFunction>())]
    hash_function: Option<HashFunction>,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("sign_transaction_source").required(true).args(["input_json", "input_file", "sign_with"])))]
#[command(group(ArgGroup::new("transaction_input").args(["unsigned_transaction", "unsigned_transaction_file"])))]
#[command(group(ArgGroup::new("sign_transaction_flags").multiple(true).args(["sign_with", "unsigned_transaction", "unsigned_transaction_file", "transaction_type"]).conflicts_with_all(["input_json", "input_file"])))]
pub struct SignTransactionArgs {
    #[command(flatten)]
    body: BodySource,
    /// Wallet account address or private key ID that signs.
    #[arg(long, requires_all = ["transaction_input", "transaction_type"])]
    sign_with: Option<String>,
    /// Serialized unsigned transaction.
    #[arg(long, requires = "sign_with")]
    unsigned_transaction: Option<String>,
    /// Read the serialized unsigned transaction from a file, or - for stdin.
    ///
    /// Surrounding whitespace is trimmed.
    #[arg(long, requires = "sign_with")]
    unsigned_transaction_file: Option<PathBuf>,
    /// Transaction type.
    #[arg(long = "type", requires = "sign_with", value_parser = enum_args::parser::<TransactionType>())]
    transaction_type: Option<TransactionType>,
}

#[derive(Debug, Subcommand)]
pub enum WalletCommand {
    /// List wallets.
    List,
    /// Fetch one wallet by ID.
    Get {
        /// Wallet ID.
        #[arg(long)]
        id: Uuid,
    },
    /// Create a wallet from flags, or from a `CreateWalletIntent` parameters
    /// object.
    Create(CreateWalletArgs),
    /// Update a wallet from an `UpdateWalletIntent` parameters object.
    Update(BodyArgs),
    /// Manage wallet accounts.
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum AccountCommand {
    /// List accounts in one wallet, one page at a time.
    List {
        /// Wallet holding the accounts.
        #[arg(long)]
        wallet_id: Uuid,
        /// Page size.
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=i64::from(ACCOUNT_PAGE_SIZE)))]
        limit: u32,
        /// Wallet account ID to continue after.
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Create an account from flags, or accounts from a
    /// `CreateWalletAccountsIntent` parameters object.
    Create(CreateAccountArgs),
}

#[derive(Debug, Subcommand)]
pub enum SignCommand {
    /// Sign a payload with an explicit encoding and hash function; from flags
    /// or a `SignRawPayloadIntentV2` parameters object.
    Payload(SignPayloadArgs),
    /// Sign an already serialized transaction; does not broadcast.
    Transaction(SignTransactionArgs),
}

pub enum PreparedWalletCommand {
    Query(WalletQuery),
    Mutation(WalletMutation),
}

pub enum WalletQuery {
    List,
    Get(Uuid),
    Accounts {
        wallet_id: Uuid,
        limit: u32,
        cursor: Option<String>,
    },
}

pub enum WalletMutation {
    Create(CreateWalletIntent),
    Update {
        wallet_id: Uuid,
        wallet_name: String,
    },
    CreateAccounts {
        wallet_id: Uuid,
        accounts: Vec<WalletAccountParams>,
        persist: Option<bool>,
    },
    CreateNextAccount {
        wallet_id: Uuid,
        standard: StandardFormat,
        curve: Curve,
        path_format: PathFormat,
    },
    Payload(SignRawPayloadIntentV2),
    Transaction(SignTransactionIntentV2),
}

impl WalletCommand {
    pub fn prepare(self) -> Result<PreparedWalletCommand> {
        Ok(match self {
            Self::List => PreparedWalletCommand::Query(WalletQuery::List),
            Self::Get { id } => PreparedWalletCommand::Query(WalletQuery::Get(id)),
            Self::Create(CreateWalletArgs {
                body, name: None, ..
            }) => PreparedWalletCommand::Mutation(WalletMutation::Create(body.parse()?)),
            Self::Create(CreateWalletArgs {
                name: Some(wallet_name),
                accounts,
                mnemonic_length,
                body: _,
            }) => {
                let mut taken: HashMap<AddressFormat, HashSet<String>> = HashMap::new();
                for AccountSpec { target, .. } in &accounts {
                    if let AccountTarget::Path {
                        address_format,
                        path,
                    } = target
                        && !taken
                            .entry(*address_format)
                            .or_default()
                            .insert(path.clone())
                    {
                        return Err(InvalidInput(format!(
                            "duplicate account path {path} for {}",
                            address_format.cli_name()
                        ))
                        .into());
                    }
                }
                let params = accounts
                    .into_iter()
                    .map(|AccountSpec { curve, target }| {
                        let (address_format, path) = match target {
                            AccountTarget::Path {
                                address_format,
                                path,
                            } => (address_format, path),
                            AccountTarget::Next(standard) => {
                                let used = taken.entry(standard.into()).or_default();
                                let path = standard.next_path(used);
                                used.insert(path.clone());
                                (standard.into(), path)
                            }
                        };
                        WalletAccountParams {
                            curve,
                            path_format: PathFormat::Bip32,
                            path,
                            address_format,
                            name: None,
                        }
                    })
                    .collect();
                PreparedWalletCommand::Mutation(WalletMutation::Create(CreateWalletIntent {
                    wallet_name,
                    accounts: params,
                    mnemonic_length,
                }))
            }
            Self::Update(input) => {
                let UpdateWalletIntent {
                    wallet_id,
                    wallet_name,
                } = input.parse()?;
                PreparedWalletCommand::Mutation(WalletMutation::Update {
                    wallet_id: Uuid::parse_str(&wallet_id)
                        .map_err(|error| Malformed::new("walletId must be a UUID", error))?,
                    wallet_name,
                })
            }
            Self::Account {
                command:
                    AccountCommand::List {
                        wallet_id,
                        limit,
                        cursor,
                    },
            } => PreparedWalletCommand::Query(WalletQuery::Accounts {
                wallet_id,
                limit,
                cursor,
            }),
            Self::Account {
                command:
                    AccountCommand::Create(CreateAccountArgs {
                        body,
                        wallet_id: None,
                        ..
                    }),
            } => {
                let CreateWalletAccountsIntent {
                    wallet_id,
                    accounts,
                    persist,
                } = body.parse()?;
                PreparedWalletCommand::Mutation(WalletMutation::CreateAccounts {
                    wallet_id: Uuid::parse_str(&wallet_id)
                        .map_err(|error| Malformed::new("walletId must be a UUID", error))?,
                    accounts,
                    persist,
                })
            }
            Self::Account {
                command:
                    AccountCommand::Create(CreateAccountArgs {
                        wallet_id: Some(wallet_id),
                        address_format: Some(address_format),
                        curve,
                        path_format,
                        path,
                        body: _,
                    }),
            } => {
                let Some(curve) = curve.or_else(|| inferred_curve(address_format)) else {
                    unreachable!("clap requires --curve when no curve is inferred")
                };
                PreparedWalletCommand::Mutation(match (path, StandardFormat::of(address_format)) {
                    (Some(path), _) => WalletMutation::CreateAccounts {
                        wallet_id,
                        accounts: vec![WalletAccountParams {
                            curve,
                            path_format,
                            path,
                            address_format,
                            name: None,
                        }],
                        persist: None,
                    },
                    (None, Some(standard)) => WalletMutation::CreateNextAccount {
                        wallet_id,
                        standard,
                        curve,
                        path_format,
                    },
                    (None, None) => {
                        unreachable!("clap requires --path when no conventional path exists")
                    }
                })
            }
            Self::Account {
                command: AccountCommand::Create(_),
            } => unreachable!("clap requires an address format with a wallet ID"),
        })
    }
}

impl SignCommand {
    pub fn prepare(self) -> Result<PreparedWalletCommand> {
        Ok(PreparedWalletCommand::Mutation(match self {
            Self::Payload(SignPayloadArgs {
                body,
                sign_with: None,
                ..
            }) => WalletMutation::Payload(body.parse()?),
            Self::Payload(SignPayloadArgs {
                sign_with: Some(sign_with),
                payload,
                payload_file,
                encoding: Some(encoding),
                hash_function: Some(hash_function),
                body: _,
            }) => WalletMutation::Payload(SignRawPayloadIntentV2 {
                sign_with,
                payload: match (payload, payload_file) {
                    (Some(payload), _) => payload,
                    (None, Some(path)) => {
                        let mut payload = String::from_utf8(read_input(&path, "the payload")?)
                            .map_err(|error| Malformed::new("the payload must be UTF-8", error))?;
                        if payload.ends_with('\n') {
                            payload.pop();
                            if payload.ends_with('\r') {
                                payload.pop();
                            }
                        }
                        payload
                    }
                    (None, None) => unreachable!("clap requires a payload"),
                },
                encoding,
                hash_function,
            }),
            Self::Payload(_) => unreachable!("clap requires an encoding and hash function"),
            Self::Transaction(SignTransactionArgs {
                body,
                sign_with: None,
                ..
            }) => WalletMutation::Transaction(body.parse()?),
            Self::Transaction(SignTransactionArgs {
                sign_with: Some(sign_with),
                unsigned_transaction,
                unsigned_transaction_file,
                transaction_type: Some(transaction_type),
                body: _,
            }) => WalletMutation::Transaction(SignTransactionIntentV2 {
                sign_with,
                unsigned_transaction: match (unsigned_transaction, unsigned_transaction_file) {
                    (Some(transaction), _) => transaction,
                    (None, Some(path)) => {
                        String::from_utf8(read_input(&path, "the unsigned transaction")?)
                            .map_err(|error| {
                                Malformed::new("the unsigned transaction must be UTF-8", error)
                            })?
                            .trim()
                            .to_owned()
                    }
                    (None, None) => unreachable!("clap requires a transaction"),
                },
                r#type: transaction_type,
            }),
            Self::Transaction(_) => unreachable!("clap requires a transaction type"),
        }))
    }
}

impl PreparedWalletCommand {
    pub async fn run(self, auth: ResolvedAuth) -> Result<OperationOutput> {
        match self {
            Self::Query(query) => query.run(auth).await,
            Self::Mutation(mutation) => mutation.run(auth).await,
        }
    }
}

impl WalletMutation {
    async fn run(self, auth: ResolvedAuth) -> Result<OperationOutput> {
        let (command, endpoint, kind, params) = match self {
            Self::Create(p) => (
                "wallet.create",
                "create_wallet",
                "ACTIVITY_TYPE_CREATE_WALLET",
                to_value(p)?,
            ),
            Self::Update {
                wallet_id,
                wallet_name,
            } => (
                "wallet.update",
                "update_wallet",
                "ACTIVITY_TYPE_UPDATE_WALLET",
                to_value(UpdateWalletIntent {
                    wallet_id: wallet_id.to_string(),
                    wallet_name,
                })?,
            ),
            Self::CreateAccounts {
                wallet_id,
                accounts,
                persist,
            } => (
                "wallet.account.create",
                "create_wallet_accounts",
                "ACTIVITY_TYPE_CREATE_WALLET_ACCOUNTS",
                to_value(CreateWalletAccountsIntent {
                    wallet_id: wallet_id.to_string(),
                    accounts,
                    persist,
                })?,
            ),
            Self::CreateNextAccount {
                wallet_id,
                standard,
                curve,
                path_format,
            } => {
                let address_format = AddressFormat::from(standard);
                let mut taken = HashSet::new();
                let mut cursor = String::new();
                loop {
                    let AccountPage { accounts } = query(
                        "/public/v1/query/get_wallet_accounts",
                        &GetWalletAccountsRequest {
                            organization_id: auth.org_id.to_string(),
                            wallet_id: Some(wallet_id.to_string()),
                            include_wallet_details: None,
                            pagination_options: Some(Pagination {
                                limit: ACCOUNT_PAGE_SIZE.to_string(),
                                before: String::new(),
                                after: cursor.clone(),
                            }),
                        },
                        &auth,
                    )
                    .await?;
                    let full_page = accounts.len() == ACCOUNT_PAGE_SIZE as usize;
                    let next = accounts
                        .last()
                        .map(|account| account.wallet_account_id.clone())
                        .unwrap_or_default();
                    if full_page && next == cursor {
                        bail!("wallet account pages stopped advancing after {cursor}");
                    }
                    cursor = next;
                    taken.extend(
                        accounts
                            .into_iter()
                            .filter(|account| account.address_format == address_format.api_name())
                            .map(|account| account.path),
                    );
                    if !full_page {
                        break;
                    }
                }
                (
                    "wallet.account.create",
                    "create_wallet_accounts",
                    "ACTIVITY_TYPE_CREATE_WALLET_ACCOUNTS",
                    to_value(CreateWalletAccountsIntent {
                        wallet_id: wallet_id.to_string(),
                        accounts: vec![WalletAccountParams {
                            curve,
                            path_format,
                            path: standard.next_path(&taken),
                            address_format,
                            name: None,
                        }],
                        persist: None,
                    })?,
                )
            }
            Self::Payload(p) => (
                "sign.payload",
                "sign_raw_payload",
                "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
                to_value(p)?,
            ),
            Self::Transaction(p) => (
                "sign.transaction",
                "sign_transaction",
                "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
                to_value(p)?,
            ),
        };
        submit_activity(&auth, command, endpoint, kind, &params).await
    }
}

impl WalletQuery {
    async fn run(self, auth: ResolvedAuth) -> Result<OperationOutput> {
        let client = build_turnkey_client(auth.stamper, &auth.api_base_url)?;
        let organization_id = auth.org_id.to_string();
        match self {
            Self::List => {
                let data = client
                    .get_wallets(GetWalletsRequest { organization_id })
                    .await?;
                Ok(OperationOutput::result("wallet.list", to_value(data)?))
            }
            Self::Get(id) => {
                let data = client
                    .get_wallet(GetWalletRequest {
                        organization_id,
                        wallet_id: id.to_string(),
                    })
                    .await?;
                if data.wallet.is_none() {
                    return Err(MissingResource::new("wallet", id.to_string()).into());
                }
                Ok(OperationOutput::result("wallet.get", to_value(data)?))
            }
            Self::Accounts {
                wallet_id,
                limit,
                cursor,
            } => {
                let GetWalletAccountsResponse { accounts } = client
                    .get_wallet_accounts(GetWalletAccountsRequest {
                        organization_id,
                        wallet_id: Some(wallet_id.to_string()),
                        include_wallet_details: None,
                        pagination_options: Some(Pagination {
                            limit: limit.to_string(),
                            before: String::new(),
                            after: cursor.unwrap_or_default(),
                        }),
                    })
                    .await?;
                let next = if accounts.len() == limit as usize {
                    accounts.last().map(|account| &account.wallet_account_id)
                } else {
                    None
                };
                let next = to_value(next)?;
                Ok(OperationOutput::result(
                    "wallet.account.list",
                    json!({"accounts": accounts, "nextCursor": next}),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use clap::{Parser, error::ErrorKind};

    use super::*;

    #[derive(Debug, Parser)]
    struct WalletParser {
        #[command(subcommand)]
        command: WalletCommand,
    }

    #[derive(Debug, Parser)]
    struct SignParser {
        #[command(subcommand)]
        command: SignCommand,
    }

    #[test]
    fn conflicting_or_missing_inputs_fail_during_parsing() {
        assert_eq!(
            WalletParser::try_parse_from(["wallet", "create"])
                .unwrap_err()
                .kind(),
            ErrorKind::MissingRequiredArgument
        );
        let both = "wallet create --input-json {} --input-file x".split(' ');
        assert_eq!(
            WalletParser::try_parse_from(both).unwrap_err().kind(),
            ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn wallet_uuid_is_checked_before_authentication() {
        assert_eq!(
            WalletParser::try_parse_from(["wallet", "get", "--id", "not-an-id"])
                .unwrap_err()
                .kind(),
            ErrorKind::ValueValidation
        );
        let parsed = WalletParser::try_parse_from([
            "wallet",
            "update",
            "--input-json",
            r#"{"walletId":"bad","walletName":"next"}"#,
        ])
        .unwrap();
        let error = parsed
            .command
            .prepare()
            .err()
            .expect("prepare should have failed");
        let malformed = error
            .downcast_ref::<Malformed>()
            .expect("a malformed wallet id is a Malformed error");
        assert_eq!(malformed.to_string(), "walletId must be a UUID");
    }

    #[test]
    fn signing_requires_explicit_algorithm_inputs() {
        let parsed = SignParser::try_parse_from([
            "sign",
            "payload",
            "--input-json",
            r#"{"signWith":"opaque-key","payload":"00"}"#,
        ])
        .unwrap();
        let error = parsed
            .command
            .prepare()
            .err()
            .expect("prepare should have failed");
        let malformed = error
            .downcast_ref::<Malformed>()
            .expect("missing algorithm inputs are a Malformed error");
        assert_eq!(malformed.to_string(), "invalid operation parameters");
    }

    #[test]
    fn signing_preserves_opaque_key_identifiers() {
        let parsed = SignParser::try_parse_from(["sign", "transaction", "--input-json", r#"{"signWith":"opaque-key","unsignedTransaction":"00","type":"TRANSACTION_TYPE_ETHEREUM"}"#]).unwrap();
        let PreparedWalletCommand::Mutation(WalletMutation::Transaction(params)) =
            parsed.command.prepare().unwrap()
        else {
            panic!("expected prepared transaction")
        };
        assert_eq!(params.sign_with, "opaque-key");
    }

    fn wallet(args: &str) -> Result<WalletParser, clap::Error> {
        WalletParser::try_parse_from(args.split(' '))
    }

    fn sign(args: &str) -> Result<SignParser, clap::Error> {
        SignParser::try_parse_from(args.split(' '))
    }

    #[test]
    fn flag_inputs_are_checked_during_parsing() {
        let account = format!("wallet account create --wallet-id {}", Uuid::nil());
        for (args, kind) in [
            (
                "wallet create --name x --input-json {}",
                ErrorKind::ArgumentConflict,
            ),
            (
                "wallet create --account ethereum",
                ErrorKind::MissingRequiredArgument,
            ),
            (
                "wallet create --name x --mnemonic-length 13",
                ErrorKind::ValueValidation,
            ),
            (
                "wallet create --name x --account nonsense",
                ErrorKind::ValueValidation,
            ),
            (
                "wallet create --name x --account ADDRESS_FORMAT_ETHEREUM",
                ErrorKind::ValueValidation,
            ),
            (
                "wallet create --name x --account sui",
                ErrorKind::ValueValidation,
            ),
            (
                "wallet create --name x --account ethereum:",
                ErrorKind::ValueValidation,
            ),
            (
                &format!("{account} --address-format Ethereum"),
                ErrorKind::InvalidValue,
            ),
            (
                &format!("{account} --address-format ethereum --path-format PATH_FORMAT_BIP32"),
                ErrorKind::InvalidValue,
            ),
            (
                &format!("{account} --address-format sui"),
                ErrorKind::MissingRequiredArgument,
            ),
            (
                &format!("{account} --address-format sui --curve ed25519"),
                ErrorKind::MissingRequiredArgument,
            ),
            (
                &format!("{account} --address-format tron --path m/0"),
                ErrorKind::MissingRequiredArgument,
            ),
            (
                &format!("{account} --address-format ethereum --input-json {{}}"),
                ErrorKind::ArgumentConflict,
            ),
        ] {
            assert_eq!(wallet(args).unwrap_err().kind(), kind, "{args}");
        }
        for (args, kind) in [
            (
                "sign payload --sign-with a --payload x --hash-function sha256",
                ErrorKind::MissingRequiredArgument,
            ),
            (
                "sign payload --sign-with a --payload x --encoding text-utf8",
                ErrorKind::MissingRequiredArgument,
            ),
            (
                "sign payload --sign-with a --encoding text-utf8 --hash-function sha256",
                ErrorKind::MissingRequiredArgument,
            ),
            (
                "sign payload --sign-with a --payload x --payload-file y --encoding text-utf8 --hash-function sha256",
                ErrorKind::ArgumentConflict,
            ),
            (
                "sign payload --sign-with a --payload x --encoding text_utf8 --hash-function sha256",
                ErrorKind::InvalidValue,
            ),
            (
                "sign payload --input-json {} --encoding text-utf8",
                ErrorKind::ArgumentConflict,
            ),
            (
                "sign transaction --sign-with a --unsigned-transaction 00",
                ErrorKind::MissingRequiredArgument,
            ),
            (
                "sign transaction --sign-with a --type ethereum",
                ErrorKind::MissingRequiredArgument,
            ),
            (
                "sign transaction --sign-with a --unsigned-transaction 00 --type unspecified",
                ErrorKind::InvalidValue,
            ),
        ] {
            assert_eq!(sign(args).unwrap_err().kind(), kind, "{args}");
        }
        let explicit = format!("{account} --address-format sui --curve ed25519 --path m/0");
        wallet(&explicit).unwrap();
    }

    #[test]
    fn predicted_wallet_paths_skip_explicit_paths_in_any_order() {
        let PreparedWalletCommand::Mutation(WalletMutation::Create(intent)) = wallet(
            "wallet create --name w --account ethereum --account ethereum:m/44'/60'/0'/0/0 --account ethereum --account solana",
        )
        .unwrap()
        .command
        .prepare()
        .unwrap() else {
            panic!("expected a wallet create intent")
        };
        let paths: Vec<(AddressFormat, Curve, &str)> = intent
            .accounts
            .iter()
            .map(|account| (account.address_format, account.curve, account.path.as_str()))
            .collect();
        assert_eq!(
            paths,
            [
                (
                    AddressFormat::Ethereum,
                    Curve::Secp256k1,
                    "m/44'/60'/1'/0/0"
                ),
                (
                    AddressFormat::Ethereum,
                    Curve::Secp256k1,
                    "m/44'/60'/0'/0/0"
                ),
                (
                    AddressFormat::Ethereum,
                    Curve::Secp256k1,
                    "m/44'/60'/2'/0/0"
                ),
                (AddressFormat::Solana, Curve::Ed25519, "m/44'/501'/0'/0'"),
            ]
        );
    }

    #[test]
    fn a_repeated_explicit_wallet_path_is_invalid_input() {
        let error = wallet("wallet create --name w --account ethereum:m/0 --account ethereum:m/0")
            .unwrap()
            .command
            .prepare()
            .err()
            .expect("prepare should have failed");
        assert_eq!(
            error
                .downcast_ref::<InvalidInput>()
                .map(ToString::to_string),
            Some("duplicate account path m/0 for ethereum".to_owned())
        );
    }

    #[test]
    fn payload_files_drop_one_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        for (contents, payload) in [
            ("hello", "hello"),
            ("hello\n", "hello"),
            ("hello\r\n", "hello"),
            ("hello\n\n", "hello\n"),
            (" hello \n", " hello "),
        ] {
            let file = dir.path().join("payload");
            fs::write(&file, contents).unwrap();
            let args = format!(
                "sign payload --sign-with a --payload-file {} --encoding text-utf8 --hash-function sha256",
                file.display()
            );
            let PreparedWalletCommand::Mutation(WalletMutation::Payload(intent)) =
                sign(&args).unwrap().command.prepare().unwrap()
            else {
                panic!("expected a payload intent")
            };
            assert_eq!(intent.payload, payload, "{contents:?}");
        }
    }
}
