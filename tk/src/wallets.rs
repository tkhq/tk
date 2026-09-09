//! Wallet discovery and typed signing inputs.
use crate::{
    auth::ResolvedAuth,
    errors::InvalidInput,
    operations::{OperationOutput, envelope, submit},
    resources::BodyArgs,
};
use anyhow::Result;
use clap::Subcommand;
use serde_json::to_value;
use turnkey_client::generated::{
    GetWalletAccountsRequest, GetWalletRequest, GetWalletsRequest,
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
    List {
        #[arg(long)]
        wallet_id: Uuid,
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
    Accounts(Uuid),
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
                command: AccountCommand::List { wallet_id },
            } => PreparedWalletCommand::Accounts(wallet_id),
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
        let organization_id = auth.org_id.clone();
        macro_rules! submit_operation {
            ($command:literal, $endpoint:literal, $kind:literal, $params:expr) => {
                submit(
                    $command,
                    concat!("/public/v1/submit/", $endpoint),
                    &envelope($kind, &organization_id, &$params)?,
                    &auth.api_base_url,
                    &auth.stamper,
                )
                .await?
            };
        }
        macro_rules! client {
            () => {
                crate::auth::build_turnkey_client(auth.stamper, &auth.api_base_url)?
            };
        }
        let output = match self {
            Self::List => {
                let data = client!()
                    .get_wallets(GetWalletsRequest { organization_id })
                    .await?;
                OperationOutput::result("wallet.list", to_value(data)?)
            }
            Self::Get(id) => {
                let data = client!()
                    .get_wallet(GetWalletRequest {
                        organization_id,
                        wallet_id: id.to_string(),
                    })
                    .await?;
                data.wallet
                    .as_ref()
                    .ok_or_else(|| crate::errors::MissingResource::new("wallet", id.to_string()))?;
                OperationOutput::result("wallet.get", to_value(data)?)
            }
            Self::Accounts(id) => {
                let data = client!()
                    .get_wallet_accounts(GetWalletAccountsRequest {
                        organization_id,
                        wallet_id: Some(id.to_string()),
                        include_wallet_details: None,
                        pagination_options: None,
                    })
                    .await?;
                OperationOutput::result("wallet.account.list", to_value(data)?)
            }
            Self::Create(parameters) => {
                submit_operation!(
                    "wallet.create",
                    "create_wallet",
                    "ACTIVITY_TYPE_CREATE_WALLET",
                    parameters
                )
            }
            Self::Update(parameters) => {
                submit_operation!(
                    "wallet.update",
                    "update_wallet",
                    "ACTIVITY_TYPE_UPDATE_WALLET",
                    parameters
                )
            }
            Self::CreateAccounts(parameters) => {
                submit_operation!(
                    "wallet.account.create",
                    "create_wallet_accounts",
                    "ACTIVITY_TYPE_CREATE_WALLET_ACCOUNTS",
                    parameters
                )
            }
            Self::Payload(parameters) => {
                submit_operation!(
                    "sign.payload",
                    "sign_raw_payload",
                    "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
                    parameters
                )
            }
            Self::Transaction(parameters) => {
                submit_operation!(
                    "sign.transaction",
                    "sign_transaction",
                    "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
                    parameters
                )
            }
        };
        Ok(output)
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
        assert!(
            WalletParser::try_parse_from([
                "wallet",
                "create",
                "--input-json",
                "{}",
                "--input-file",
                "x"
            ])
            .is_err()
        );
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
    #[tokio::test]
    async fn transaction_submission_is_typed_and_not_retried_when_pending() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{body_partial_json, method, path},
        };
        let server = MockServer::start().await;
        let org = "00000000-0000-4000-8000-000000000001";
        let auth = || {
            crate::auth::ResolvedAuth::for_tests(
                org,
                &server.uri(),
                turnkey_api_key_stamper::TurnkeyP256ApiKey::generate(),
            )
        };
        Mock::given(method("POST"))
            .and(path("/public/v1/submit/sign_transaction"))
            .and(body_partial_json(serde_json::json!({"organizationId": org, "type": "ACTIVITY_TYPE_SIGN_TRANSACTION_V2", "parameters": {"signWith": "opaque-key", "unsignedTransaction": "00", "type": "TRANSACTION_TYPE_ETHEREUM"}})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"activity":{"id":"pending-id","status":"ACTIVITY_STATUS_CONSENSUS_NEEDED"}})))
            .expect(1).mount(&server).await;
        let parsed = SignParser::try_parse_from(["sign", "transaction", "--input-json", r#"{"signWith":"opaque-key","unsignedTransaction":"00","type":"TRANSACTION_TYPE_ETHEREUM"}"#]).unwrap();
        let output = parsed.command.prepare().unwrap().run(auth()).await.unwrap();
        let value = serde_json::to_value(output).unwrap();
        assert_eq!(value["status"], "pending");
        assert_eq!(value["activity"]["id"], "pending-id");
        server.verify().await;
        for response in [serde_json::json!({}), serde_json::json!({"wallet": null})] {
            server.reset().await;
            Mock::given(method("POST"))
                .and(path("/public/v1/query/get_wallet"))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .expect(1)
                .mount(&server)
                .await;
            let error = PreparedWalletCommand::Get(Uuid::parse_str(org).unwrap())
                .run(auth())
                .await
                .unwrap_err();
            assert!(
                error
                    .downcast_ref::<crate::errors::MissingResource>()
                    .is_some()
            );
            server.verify().await;
        }
    }
}
