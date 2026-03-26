use std::collections::BTreeMap;
use std::fs;

use tempfile::tempdir;
use turnkey_auth::config::Config;

#[test]
fn config_resolution_prefers_env_over_global_over_default() {
    let temp = tempdir().expect("temp dir should exist");
    let config_path = temp.path().join("tk.toml");
    fs::write(
        &config_path,
        r#"[turnkey]
organizationId = "file-org"
apiPublicKey = "file-pub"
apiPrivateKey = "file-priv"
signingAddress = "file-addr"
signingPublicKey = "file-spk"
"#,
    )
    .expect("config file should be written");

    let env = BTreeMap::from([
        ("TURNKEY_ORGANIZATION_ID".to_string(), "env-org".to_string()),
        ("TURNKEY_API_PUBLIC_KEY".to_string(), "env-pub".to_string()),
        (
            "TURNKEY_API_PRIVATE_KEY".to_string(),
            "env-priv".to_string(),
        ),
    ]);

    let config = Config::resolve_from_map(&config_path, &env).expect("config should resolve");

    assert_eq!(config.organization_id, "env-org");
    assert_eq!(config.api_public_key, "env-pub");
    assert_eq!(config.api_private_key, "env-priv");
    // signing_address and signing_public_key come from config file only (no env override).
    assert_eq!(config.signing_address, "file-addr");
    assert_eq!(config.signing_public_key, "file-spk");
    assert_eq!(config.api_base_url, "https://api.turnkey.com");
}
