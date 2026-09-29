use crate::{
    auth::{ResolvedAuth, build_turnkey_client},
    errors::{Malformed, MissingResource},
    operations::{OperationOutput, submit_activity},
    resources::BodyArgs,
};
use anyhow::Result;
use clap::Subcommand;
use serde_json::{json, to_value};
use turnkey_client::generated::{
    GetWalletAccountsRequest, GetWalletAccountsResponse, GetWalletRequest, GetWalletsRequest,
    external::options::v1::Pagination,
    immutable::activity::v1::{
        CreateWalletAccountsIntent, CreateWalletIntent, SignRawPayloadIntentV2,
        SignTransactionIntentV2, UpdateWalletIntent, WalletAccountParams,
    },
};
use uuid::Uuid;

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
    /// Create a wallet from a `CreateWalletIntent` parameters object.
    Create(BodyArgs),
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
    /// Create accounts from a `CreateWalletAccountsIntent` parameters object.
    Create(BodyArgs),
}

#[derive(Debug, Subcommand)]
pub enum SignCommand {
    /// Sign a payload with explicit encoding and hash function in JSON input.
    Payload(BodyArgs),
    /// Sign an already serialized transaction; does not broadcast.
    Transaction(BodyArgs),
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
    Payload(SignRawPayloadIntentV2),
    Transaction(SignTransactionIntentV2),
}

impl WalletCommand {
    pub fn prepare(self) -> Result<PreparedWalletCommand> {
        Ok(match self {
            Self::List => PreparedWalletCommand::Query(WalletQuery::List),
            Self::Get { id } => PreparedWalletCommand::Query(WalletQuery::Get(id)),
            Self::Create(input) => {
                PreparedWalletCommand::Mutation(WalletMutation::Create(input.parse()?))
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
                command: AccountCommand::Create(input),
            } => {
                let CreateWalletAccountsIntent {
                    wallet_id,
                    accounts,
                    persist,
                } = input.parse()?;
                PreparedWalletCommand::Mutation(WalletMutation::CreateAccounts {
                    wallet_id: Uuid::parse_str(&wallet_id)
                        .map_err(|error| Malformed::new("walletId must be a UUID", error))?,
                    accounts,
                    persist,
                })
            }
        })
    }
}

impl SignCommand {
    pub fn prepare(self) -> Result<PreparedWalletCommand> {
        Ok(PreparedWalletCommand::Mutation(match self {
            Self::Payload(input) => WalletMutation::Payload(input.parse()?),
            Self::Transaction(input) => WalletMutation::Transaction(input.parse()?),
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
    use super::*;
    use clap::Parser;
    use clap::error::ErrorKind;
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
