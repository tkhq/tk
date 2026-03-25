use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use tempfile::tempdir;
use turnkey_auth::config::{Config, default_config_dir_from_home, default_config_file_from_home};

#[test]
fn default_config_paths_are_derived_from_home() {
    let home = Path::new("/tmp/home");

    assert_eq!(
        default_config_dir_from_home(home),
        home.join(".config").join("turnkey").join("tk")
    );
    assert_eq!(
        default_config_file_from_home(home),
        home.join(".config")
            .join("turnkey")
            .join("tk")
            .join("tk.toml")
    );
}

#[test]
fn config_resolution_prefers_env_over_global_over_default() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("tk.toml");
    fs::write(
        &config_path,
        r#"[turnkey]
organizationId = "file-org"
apiPublicKey = "file-pub"
apiPrivateKey = "file-priv"
privateKeyId = "file-key"
    "#,
    )
    .unwrap();

    let env = BTreeMap::from([
        ("TURNKEY_ORGANIZATION_ID".to_string(), "env-org".to_string()),
        ("TURNKEY_API_PUBLIC_KEY".to_string(), "env-pub".to_string()),
        (
            "TURNKEY_API_PRIVATE_KEY".to_string(),
            "env-priv".to_string(),
        ),
        ("TURNKEY_PRIVATE_KEY_ID".to_string(), "env-key".to_string()),
    ]);

    let config = Config::resolve_from_map(&config_path, &env).unwrap();

    assert_eq!(config.organization_id, "env-org");
    assert_eq!(config.api_public_key, "env-pub");
    assert_eq!(config.api_private_key, "env-priv");
    assert_eq!(config.private_key_id, "env-key");
    assert_eq!(config.api_base_url, "https://api.turnkey.com");
}
