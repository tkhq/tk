use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;

#[test]
fn public_key_prints_openssh_line_from_config() {
    let api_key = TurnkeyP256ApiKey::generate();
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("tk.toml");
    fs::write(
        &config_path,
        format!(
            r#"[turnkey]
organizationId = "org-id"
apiPublicKey = "{}"
apiPrivateKey = "{}"
signingAddress = "test-address"
signingPublicKey = "6666666666666666666666666666666666666666666666666666666666666666"
apiBaseUrl = "https://localhost:1"
"#,
            hex::encode(api_key.compressed_public_key()),
            hex::encode(api_key.private_key()),
        ),
    )
    .unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.arg("public-key")
        .env("TURNKEY_TK_CONFIG_PATH", &config_path);

    cmd.assert().success().stdout(predicate::str::contains(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm",
    ));
}
