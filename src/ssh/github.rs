//! GitHub's SSH host keys, read from its TLS-authenticated metadata API.

use std::{
    fmt::{self, Display, Formatter},
    time::Duration,
};

use anyhow::{Context, Result};
use reqwest::{Client, Response, header::ACCEPT};
use serde::{Deserialize, Serialize};
use ssh_key::{HashAlg, PublicKey};

use crate::auth::CLIENT_VERSION;

pub const META_URL: &str = "https://api.github.com/meta";
const TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Deserialize)]
struct Meta {
    ssh_keys: Vec<String>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Debug, Default, PartialEq))]
#[serde(rename_all = "camelCase")]
pub struct GithubHostKeys {
    host_keys: Vec<GithubHostKey>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Debug, PartialEq))]
#[serde(rename_all = "camelCase")]
struct GithubHostKey {
    fingerprint: String,
    algorithm: String,
    public_key: String,
}

impl Display for GithubHostKeys {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut keys = self.host_keys.iter();
        if let Some(GithubHostKey {
            fingerprint,
            algorithm,
            public_key: _,
        }) = keys.next()
        {
            write!(f, "{fingerprint}  {algorithm}")?;
        }
        for GithubHostKey {
            fingerprint,
            algorithm,
            public_key: _,
        } in keys
        {
            write!(f, "\n{fingerprint}  {algorithm}")?;
        }
        Ok(())
    }
}

pub fn client() -> Result<Client> {
    Client::builder()
        .user_agent(CLIENT_VERSION)
        .https_only(true)
        .timeout(TIMEOUT)
        .build()
        .context("build the GitHub metadata client")
}

pub async fn host_keys(client: &Client, url: &str) -> Result<GithubHostKeys> {
    let Meta { ssh_keys } = client
        .get(url)
        .header(ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .and_then(Response::error_for_status)
        .with_context(|| format!("fetch GitHub's SSH host keys from {url}"))?
        .json()
        .await
        .with_context(|| format!("parse GitHub's SSH host keys from {url}"))?;
    let host_keys = ssh_keys
        .into_iter()
        .map(|line| {
            let key = PublicKey::from_openssh(&line)
                .with_context(|| format!("parse GitHub SSH host key {line:?}"))?;
            Ok(GithubHostKey {
                fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
                algorithm: key.algorithm().to_string(),
                public_key: line,
            })
        })
        .collect::<Result<_>>()?;
    Ok(GithubHostKeys { host_keys })
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    use super::*;

    const ED25519: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    const ECDSA: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=";

    #[tokio::test]
    async fn host_keys_fingerprints_each_published_key() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/meta"))
            .and(header("accept", "application/vnd.github+json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ssh_key_fingerprints": {},
                "ssh_keys": [ED25519, ECDSA],
            })))
            .mount(&server)
            .await;

        let keys = host_keys(&Client::new(), &format!("{}/meta", server.uri()))
            .await
            .unwrap();

        assert_eq!(
            keys,
            GithubHostKeys {
                host_keys: vec![
                    GithubHostKey {
                        fingerprint: "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"
                            .to_string(),
                        algorithm: "ssh-ed25519".to_string(),
                        public_key: ED25519.to_string(),
                    },
                    GithubHostKey {
                        fingerprint: "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM"
                            .to_string(),
                        algorithm: "ecdsa-sha2-nistp256".to_string(),
                        public_key: ECDSA.to_string(),
                    },
                ],
            }
        );
        assert_eq!(
            keys.to_string(),
            r#"SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU  ssh-ed25519
SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM  ecdsa-sha2-nistp256"#
        );
    }

    #[tokio::test]
    async fn host_keys_fails_on_an_error_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let error = host_keys(&Client::new(), &format!("{}/meta", server.uri()))
            .await
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            format!("fetch GitHub's SSH host keys from {}/meta", server.uri())
        );
    }
}
