use std::{
    collections::HashSet,
    fs,
    io::{self, Read},
    path::PathBuf,
    str::FromStr,
};

use anyhow::Result;
use clap::{ArgGroup, Args, Subcommand};
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
    errors::{InvalidInput, Malformed, MissingResource},
    operations::{OperationOutput, query, submit_activity},
    resources::{BodyArgs, BodySource},
};

const ACCOUNT_PAGE_SIZE: u32 = 100;

trait ApiEnum: Sized {
    const PREFIX: &'static str;
    fn from_name(name: &str) -> Option<Self>;
}

macro_rules! api_enum {
    ($type:ty, $prefix:literal) => {
        impl ApiEnum for $type {
            const PREFIX: &'static str = $prefix;
            fn from_name(name: &str) -> Option<Self> {
                Self::from_str_name(name)
            }
        }
    };
}

api_enum!(AddressFormat, "ADDRESS_FORMAT_");
api_enum!(Curve, "CURVE_");
api_enum!(PathFormat, "PATH_FORMAT_");
api_enum!(PayloadEncoding, "PAYLOAD_ENCODING_");
api_enum!(HashFunction, "HASH_FUNCTION_");
api_enum!(TransactionType, "TRANSACTION_TYPE_");

/// Parses an API enum name, case-insensitively and with or without its prefix.
fn parse_api_enum<T: ApiEnum>(value: &str) -> Result<T, String> {
    let upper = value.to_ascii_uppercase().replace('-', "_");
    let parsed = T::from_name(&upper).or_else(|| T::from_name(&format!("{}{upper}", T::PREFIX)));
    match parsed {
        Some(parsed) if !upper.ends_with("UNSPECIFIED") => Ok(parsed),
        _ => Err(format!(
            "unknown value `{value}`; expected an API name such as {}…",
            T::PREFIX
        )),
    }
}

fn parse_mnemonic_length(value: &str) -> Result<i32, String> {
    match value.parse() {
        Ok(words @ (12 | 15 | 18 | 21 | 24)) => Ok(words),
        _ => Err("must be 12, 15, 18, 21, or 24".into()),
    }
}

fn read_text(path: &PathBuf, what: &str) -> Result<String> {
    if path.as_os_str() == "-" {
        let mut text = String::new();
        io::stdin()
            .read_to_string(&mut text)
            .map_err(|error| Malformed::new(format!("could not read {what} from stdin"), error))?;
        return Ok(text);
    }
    Ok(fs::read_to_string(path).map_err(|error| {
        Malformed::new(
            format!("could not read {what} from {}", path.display()),
            error,
        )
    })?)
}

fn curve_for(address_format: AddressFormat) -> Option<Curve> {
    match address_format {
        AddressFormat::Ethereum | AddressFormat::Cosmos | AddressFormat::Uncompressed => {
            Some(Curve::Secp256k1)
        }
        AddressFormat::Solana => Some(Curve::Ed25519),
        _ => None,
    }
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

    fn next_path(self, taken: &HashSet<&str>) -> String {
        (0..)
            .map(|index| self.path(index))
            .find(|path| !taken.contains(path.as_str()))
            .unwrap_or_default()
    }
}

impl TryFrom<AddressFormat> for StandardFormat {
    type Error = InvalidInput;

    fn try_from(address_format: AddressFormat) -> Result<Self, InvalidInput> {
        match address_format {
            AddressFormat::Ethereum => Ok(Self::Ethereum),
            AddressFormat::Cosmos => Ok(Self::Cosmos),
            AddressFormat::Solana => Ok(Self::Solana),
            AddressFormat::Uncompressed => Ok(Self::Uncompressed),
            AddressFormat::Compressed => Ok(Self::Compressed),
            other => Err(InvalidInput(format!(
                "no conventional derivation path for {}; pass --path",
                other.as_str_name()
            ))),
        }
    }
}

fn require_curve(address_format: AddressFormat, curve: Option<Curve>, hint: &str) -> Result<Curve> {
    curve.or_else(|| curve_for(address_format)).ok_or_else(|| {
        InvalidInput(format!(
            "cannot infer the curve for {}; {hint}",
            address_format.as_str_name()
        ))
        .into()
    })
}

/// An account to create with a new wallet, written `ADDRESS_FORMAT[:PATH]`.
#[derive(Clone, Debug)]
pub struct AccountSpec {
    address_format: AddressFormat,
    path: Option<String>,
}

impl FromStr for AccountSpec {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, String> {
        let (format, path) = match value.split_once(':') {
            Some((format, path)) if !path.is_empty() => (format, Some(path.to_owned())),
            Some(_) => return Err("the path after `:` must not be empty".into()),
            None => (value, None),
        };
        Ok(Self {
            address_format: parse_api_enum(format)?,
            path,
        })
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
    /// Account to create with the wallet; without a path, the conventional
    /// path for the address format is used.
    ///
    /// The curve is inferred from the address format. With no `--account`,
    /// the wallet is created without accounts.
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
    #[arg(long, requires = "wallet_id", value_parser = parse_api_enum::<AddressFormat>)]
    address_format: Option<AddressFormat>,
    /// Curve of the account; inferred from the address format when omitted.
    #[arg(long, requires = "wallet_id", value_parser = parse_api_enum::<Curve>)]
    curve: Option<Curve>,
    /// Derivation path format.
    #[arg(long, requires = "wallet_id", value_parser = parse_api_enum::<PathFormat>, default_value = "PATH_FORMAT_BIP32")]
    path_format: PathFormat,
    /// Derivation path; the next unused conventional path is used when omitted.
    #[arg(long, requires = "wallet_id")]
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
    /// Read the payload verbatim from a file, or - for stdin.
    ///
    /// A trailing newline is part of the payload.
    #[arg(long, requires = "sign_with")]
    payload_file: Option<PathBuf>,
    /// How the payload is encoded.
    #[arg(long, requires = "sign_with", value_parser = parse_api_enum::<PayloadEncoding>)]
    encoding: Option<PayloadEncoding>,
    /// Hash function applied to the payload before signing.
    #[arg(long, requires = "sign_with", value_parser = parse_api_enum::<HashFunction>)]
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
    #[arg(long = "type", requires = "sign_with", value_parser = parse_api_enum::<TransactionType>)]
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
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: u32,
        /// Wallet account ID to continue after.
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Create an account from flags, or accounts from a
    /// `CreateWalletAccountsIntent` parameters object.
    ///
    /// Without `--path`, the path is the lowest conventional path for the
    /// address format that no account of that format in the wallet uses yet.
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
        address_format: AddressFormat,
        curve: Curve,
        path_format: PathFormat,
        standard: StandardFormat,
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
                let mut counts: Vec<(AddressFormat, usize)> = Vec::new();
                let mut params = Vec::with_capacity(accounts.len());
                for AccountSpec {
                    address_format,
                    path,
                } in accounts
                {
                    let curve =
                        require_curve(address_format, None, "use --input-json to name the curve")?;
                    let index = match counts
                        .iter_mut()
                        .find(|(format, _)| *format == address_format)
                    {
                        Some((_, count)) => {
                            *count += 1;
                            *count
                        }
                        None => {
                            counts.push((address_format, 0));
                            0
                        }
                    };
                    let path = match path {
                        Some(path) => path,
                        None => StandardFormat::try_from(address_format)?.path(index),
                    };
                    params.push(WalletAccountParams {
                        curve,
                        path_format: PathFormat::Bip32,
                        path,
                        address_format,
                        name: None,
                    });
                }
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
                let curve = require_curve(address_format, curve, "pass --curve")?;
                PreparedWalletCommand::Mutation(match path {
                    Some(path) => WalletMutation::CreateAccounts {
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
                    None => WalletMutation::CreateNextAccount {
                        wallet_id,
                        address_format,
                        curve,
                        path_format,
                        standard: address_format.try_into()?,
                    },
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
                    (None, Some(path)) => read_text(&path, "the payload")?,
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
                    (None, Some(path)) => read_text(&path, "the unsigned transaction")?
                        .trim()
                        .to_owned(),
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
                address_format,
                curve,
                path_format,
                standard,
            } => {
                let mut paths = Vec::new();
                let mut cursor = String::new();
                loop {
                    let GetWalletAccountsResponse { accounts } = query(
                        "/public/v1/query/get_wallet_accounts",
                        &GetWalletAccountsRequest {
                            organization_id: auth.org_id.to_string(),
                            wallet_id: Some(wallet_id.to_string()),
                            include_wallet_details: None,
                            pagination_options: Some(Pagination {
                                limit: ACCOUNT_PAGE_SIZE.to_string(),
                                before: String::new(),
                                after: cursor,
                            }),
                        },
                        &auth,
                    )
                    .await?;
                    let full_page = accounts.len() == ACCOUNT_PAGE_SIZE as usize;
                    cursor = accounts
                        .last()
                        .map(|account| account.wallet_account_id.clone())
                        .unwrap_or_default();
                    paths.extend(
                        accounts
                            .into_iter()
                            .filter(|account| account.address_format == address_format)
                            .map(|account| account.path),
                    );
                    if !full_page {
                        break;
                    }
                }
                let taken = paths.iter().map(String::as_str).collect();
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
}
