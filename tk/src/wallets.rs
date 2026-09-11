use crate::{
    auth::{ResolvedAuth, build_turnkey_client},
    errors::{InvalidInput, MissingResource},
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
        SignTransactionIntentV2, UpdateWalletIntent,
    },
};
use uuid::Uuid;

#[derive(Debug, Subcommand)]
pub enum WalletCommand {
    List,
    Get {
        id: Uuid,
    },
    Create(BodyArgs),
    Update(BodyArgs),
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum AccountCommand {
    /// List accounts in one wallet, one page at a time.
    List {
        #[arg(long)]
        wallet_id: Uuid,
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: u32,
        /// API after cursor (wallet account ID); pagination is explicitly caller-driven.
        #[arg(long)]
        cursor: Option<String>,
    },
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
    List,
    Get(Uuid),
    Create(CreateWalletIntent),
    Update(UpdateWalletIntent),
    Accounts {
        wallet_id: Uuid,
        limit: u32,
        cursor: Option<String>,
    },
    CreateAccounts(CreateWalletAccountsIntent),
    Payload(SignRawPayloadIntentV2),
    Transaction(SignTransactionIntentV2),
}

impl WalletCommand {
    pub fn prepare(self) -> Result<PreparedWalletCommand> {
        Ok(match self {
            Self::List => PreparedWalletCommand::List,
            Self::Get { id } => PreparedWalletCommand::Get(id),
            Self::Create(input) => PreparedWalletCommand::Create(input.parse()?),
            Self::Update(input) => {
                let params: UpdateWalletIntent = input.parse()?;
                Uuid::parse_str(&params.wallet_id)
                    .map_err(|_| InvalidInput("walletId must be a UUID".into()))?;
                PreparedWalletCommand::Update(params)
            }
            Self::Account {
                command:
                    AccountCommand::List {
                        wallet_id,
                        limit,
                        cursor,
                    },
            } => PreparedWalletCommand::Accounts {
                wallet_id,
                limit,
                cursor,
            },
            Self::Account {
                command: AccountCommand::Create(input),
            } => {
                let params: CreateWalletAccountsIntent = input.parse()?;
                Uuid::parse_str(&params.wallet_id)
                    .map_err(|_| InvalidInput("walletId must be a UUID".into()))?;
                PreparedWalletCommand::CreateAccounts(params)
            }
        })
    }
}

impl SignCommand {
    pub fn prepare(self) -> Result<PreparedWalletCommand> {
        Ok(match self {
            Self::Payload(input) => PreparedWalletCommand::Payload(input.parse()?),
            Self::Transaction(input) => PreparedWalletCommand::Transaction(input.parse()?),
        })
    }
}

impl PreparedWalletCommand {
    pub async fn run(self, auth: ResolvedAuth) -> Result<OperationOutput> {
        let (command, endpoint, kind, params) = match self {
            Self::Create(p) => (
                "wallet.create",
                "create_wallet",
                "ACTIVITY_TYPE_CREATE_WALLET",
                to_value(p)?,
            ),
            Self::Update(p) => (
                "wallet.update",
                "update_wallet",
                "ACTIVITY_TYPE_UPDATE_WALLET",
                to_value(p)?,
            ),
            Self::CreateAccounts(p) => (
                "wallet.account.create",
                "create_wallet_accounts",
                "ACTIVITY_TYPE_CREATE_WALLET_ACCOUNTS",
                to_value(p)?,
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
            query => return query.query(auth).await,
        };
        submit_activity(&auth, command, endpoint, kind, &params).await
    }

    async fn query(self, auth: ResolvedAuth) -> Result<OperationOutput> {
        let client = build_turnkey_client(auth.stamper, &auth.api_base_url)?;
        let organization_id = auth.org_id;
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
            _ => unreachable!("mutations are submitted by run"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[derive(Parser)]
    struct WalletParser {
        #[command(subcommand)]
        command: WalletCommand,
    }

    #[derive(Parser)]
    struct SignParser {
        #[command(subcommand)]
        command: SignCommand,
    }

    #[test]
    fn conflicting_or_missing_inputs_fail_during_parsing() {
        assert!(WalletParser::try_parse_from(["wallet", "create"]).is_err());
        let both = "wallet create --input-json {} --input-file x".split(' ');
        assert!(WalletParser::try_parse_from(both).is_err());
    }

    #[test]
    fn wallet_uuid_is_checked_before_authentication() {
        assert!(WalletParser::try_parse_from(["wallet", "get", "not-an-id"]).is_err());
        let parsed = WalletParser::try_parse_from([
            "wallet",
            "update",
            "--input-json",
            r#"{"walletId":"bad","walletName":"next"}"#,
        ])
        .unwrap();
        assert!(parsed.command.prepare().is_err());
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
        assert!(parsed.command.prepare().is_err());
    }

    #[test]
    fn signing_preserves_opaque_key_identifiers() {
        let parsed = SignParser::try_parse_from(["sign", "transaction", "--input-json", r#"{"signWith":"opaque-key","unsignedTransaction":"00","type":"TRANSACTION_TYPE_ETHEREUM"}"#]).unwrap();
        let PreparedWalletCommand::Transaction(params) = parsed.command.prepare().unwrap() else {
            panic!("expected prepared transaction")
        };
        assert_eq!(params.sign_with, "opaque-key");
    }
}
