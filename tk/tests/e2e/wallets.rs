use crate::run::{Run, result};
use serde_json::{Value, json};

const UNSIGNED_EIP1559_TX: &str =
    "02df0180010182520894000000000000000000000000000000000000dead8080c0";

fn eth_account(path: &str) -> Value {
    json!({
        "curve": "CURVE_SECP256K1",
        "pathFormat": "PATH_FORMAT_BIP32",
        "path": path,
        "addressFormat": "ADDRESS_FORMAT_ETHEREUM",
    })
}

#[test]
#[ignore]
fn wallet_create_get_update_and_account_pagination() {
    let run = Run::new();
    let name = run.name("wallet");
    let created = run.submit(
        run.admin().args([
            "wallet",
            "create",
            "--input-json",
            &json!({"walletName": name, "accounts": []}).to_string(),
        ]),
        "wallet.create",
    );
    assert_eq!(
        created["data"]["activity"]["type"],
        "ACTIVITY_TYPE_CREATE_WALLET"
    );
    let wallet_id = result(&created, "createWalletResult")["walletId"]
        .as_str()
        .unwrap()
        .to_string();

    let got = run.ok(run.admin().args(["wallet", "get", "--id", &wallet_id]));
    assert_eq!(got["command"], "wallet.get");
    assert_eq!(got["data"]["wallet"]["walletId"], wallet_id);
    assert_eq!(got["data"]["wallet"]["walletName"], name);

    let renamed = run.name("wallet-renamed");
    let updated = run.submit(
        run.admin().args([
            "wallet",
            "update",
            "--input-json",
            &json!({"walletId": wallet_id, "walletName": renamed}).to_string(),
        ]),
        "wallet.update",
    );
    assert_eq!(
        result(&updated, "updateWalletResult")["walletId"],
        wallet_id
    );
    let got = run.ok(run.admin().args(["wallet", "get", "--name", &renamed]));
    assert_eq!(got["data"]["wallet"]["walletId"], wallet_id);
    assert_eq!(got["data"]["wallet"]["walletName"], renamed);

    let accounts = run.submit(
        run.admin().args([
            "wallet",
            "account",
            "create",
            "--input-json",
            &json!({
                "walletId": wallet_id,
                "accounts": [
                    eth_account("m/44'/60'/0'/0/0"),
                    eth_account("m/44'/60'/0'/0/1"),
                    eth_account("m/44'/60'/0'/0/2"),
                ],
            })
            .to_string(),
        ]),
        "wallet.account.create",
    );
    assert_eq!(
        result(&accounts, "createWalletAccountsResult")["addresses"]
            .as_array()
            .unwrap()
            .len(),
        3
    );

    let first = run.ok(run.admin().args([
        "wallet",
        "account",
        "list",
        "--wallet-id",
        &wallet_id,
        "--limit",
        "2",
    ]));
    assert_eq!(first["command"], "wallet.account.list");
    let page_one = first["data"]["accounts"].as_array().unwrap();
    assert_eq!(page_one.len(), 2);
    assert_eq!(first["data"]["nextCursor"], page_one[1]["walletAccountId"]);
    let cursor = page_one[1]["walletAccountId"].as_str().unwrap();
    let second = run.ok(run.admin().args([
        "wallet",
        "account",
        "list",
        "--wallet-id",
        &wallet_id,
        "--limit",
        "2",
        "--cursor",
        cursor,
    ]));
    let page_two = second["data"]["accounts"].as_array().unwrap();
    assert_eq!(page_two.len(), 1);
    assert_eq!(second["data"]["nextCursor"], Value::Null);
    let mut paths: Vec<&str> = page_one
        .iter()
        .chain(page_two)
        .map(|account| account["path"].as_str().unwrap())
        .collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        ["m/44'/60'/0'/0/0", "m/44'/60'/0'/0/1", "m/44'/60'/0'/0/2"]
    );
}

#[test]
#[ignore]
fn sign_payload_and_transaction() {
    let run = Run::new();
    let created = run.submit(
        run.admin().args([
            "wallet",
            "create",
            "--input-json",
            &json!({
                "walletName": run.name("signer"),
                "accounts": [eth_account("m/44'/60'/0'/0/0")],
            })
            .to_string(),
        ]),
        "wallet.create",
    );
    let address = result(&created, "createWalletResult")["addresses"][0]
        .as_str()
        .unwrap()
        .to_string();

    let digest = format!("0x{}", "11".repeat(32));
    let signed = run.submit(
        run.admin().args([
            "sign",
            "payload",
            "--input-json",
            &json!({
                "signWith": address,
                "payload": digest,
                "encoding": "PAYLOAD_ENCODING_HEXADECIMAL",
                "hashFunction": "HASH_FUNCTION_NO_OP",
            })
            .to_string(),
        ]),
        "sign.payload",
    );
    assert_eq!(signed["status"], "completed");
    assert_eq!(
        signed["data"]["activity"]["type"],
        "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2"
    );
    let signature = result(&signed, "signRawPayloadResult");
    assert_eq!(signature["r"].as_str().unwrap().len(), 64);
    assert_eq!(signature["s"].as_str().unwrap().len(), 64);
    assert!(["00", "01"].contains(&signature["v"].as_str().unwrap()));

    let signed = run.submit(
        run.admin().args([
            "sign",
            "transaction",
            "--input-json",
            &json!({
                "signWith": address,
                "unsignedTransaction": UNSIGNED_EIP1559_TX,
                "type": "TRANSACTION_TYPE_ETHEREUM",
            })
            .to_string(),
        ]),
        "sign.transaction",
    );
    assert_eq!(signed["status"], "completed");
    assert_eq!(
        signed["data"]["activity"]["type"],
        "ACTIVITY_TYPE_SIGN_TRANSACTION_V2"
    );
    let tx = result(&signed, "signTransactionResult")["signedTransaction"]
        .as_str()
        .unwrap();
    assert!(tx.starts_with("02"), "not a type-2 transaction: {tx}");
    assert!(tx.len() > UNSIGNED_EIP1559_TX.len());
    assert!(hex::decode(tx).is_ok());
}
