use std::collections::BTreeMap;
use std::env;
use std::fmt::{self, Debug, Formatter};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const REQUIRED_KEYS: [&str; 3] = [
    "TK_E2E_ORGANIZATION_ID",
    "TK_E2E_API_PUBLIC_KEY",
    "TK_E2E_API_PRIVATE_KEY",
];
const BASE_URL_KEY: &str = "TK_E2E_API_BASE_URL";
const DEFAULT_BASE_URL: &str = "https://api.turnkey.com";

pub(crate) struct Secret(pub(crate) String);
impl Debug for Secret {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Debug)]
pub(crate) struct E2eConfig {
    pub(crate) organization_id: Uuid,
    pub(crate) public_key: String,
    pub(crate) private_key: Secret,
    pub(crate) api_base_url: String,
}

fn env_file() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../.env.test")
}

fn parse_env_file(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
                .unwrap_or(value);
            Some((key.trim().to_string(), value.to_string()))
        })
        .collect()
}

impl E2eConfig {
    pub(crate) fn load() -> Self {
        let path = env_file();
        let file = fs::read_to_string(&path)
            .map(|text| parse_env_file(&text))
            .unwrap_or_default();
        let lookup = |key: &str| {
            env::var(key)
                .ok()
                .filter(|v| !v.is_empty())
                .or_else(|| file.get(key).cloned())
                .filter(|v| !v.is_empty())
        };
        let missing: Vec<&str> = REQUIRED_KEYS
            .into_iter()
            .filter(|key| lookup(key).is_none())
            .collect();
        assert!(
            missing.is_empty(),
            r#"e2e configuration is incomplete: missing {missing:?}.
Set every required key in {} or in the process environment.
Required: {REQUIRED_KEYS:?}. Optional: {BASE_URL_KEY} (default {DEFAULT_BASE_URL})."#,
            path.display()
        );
        let [org, public, private] = REQUIRED_KEYS.map(|key| lookup(key).unwrap());
        Self {
            organization_id: Uuid::parse_str(&org)
                .unwrap_or_else(|_| panic!("{} must be a UUID", REQUIRED_KEYS[0])),
            public_key: public,
            private_key: Secret(private),
            api_base_url: lookup(BASE_URL_KEY).unwrap_or_else(|| DEFAULT_BASE_URL.to_string()),
        }
    }
}

#[test]
fn env_file_parser_skips_comments_and_strips_quotes() {
    let parsed = parse_env_file(
        r#"
# comment
TK_E2E_ORGANIZATION_ID=00000000-0000-4000-8000-000000000001
TK_E2E_API_PUBLIC_KEY = "02ab"
TK_E2E_API_PRIVATE_KEY='cd'
not-a-pair
"#,
    );
    assert_eq!(
        parsed,
        BTreeMap::from([
            (
                "TK_E2E_ORGANIZATION_ID".to_string(),
                "00000000-0000-4000-8000-000000000001".to_string()
            ),
            ("TK_E2E_API_PUBLIC_KEY".to_string(), "02ab".to_string()),
            ("TK_E2E_API_PRIVATE_KEY".to_string(), "cd".to_string()),
        ])
    );
}

#[test]
fn secret_debug_is_redacted() {
    assert_eq!(format!("{:?}", Secret("deadbeef".into())), "<redacted>");
    let config = E2eConfig {
        organization_id: Uuid::nil(),
        public_key: "02ab".into(),
        private_key: Secret("deadbeef".into()),
        api_base_url: DEFAULT_BASE_URL.into(),
    };
    assert!(!format!("{config:?}").contains("deadbeef"));
}

#[test]
#[ignore]
fn config_loads_from_env_test() {
    let config = E2eConfig::load();
    assert_ne!(config.organization_id, Uuid::nil());
    assert_eq!(config.api_base_url, DEFAULT_BASE_URL);
    assert!(!config.public_key.is_empty());
    assert!(!config.private_key.0.is_empty());
}
