//! Signs in with the OAuth device authorization grant: a person approves a key generated here with a passkey in the Turnkey dashboard.

use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::json;
use tokio::time::{Instant, sleep};
use tracing::debug;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    auth::{ApiBaseUrl, http_client, read_key},
    errors::{DeviceLoginRefused, Malformed, UnexpectedHttpStatus},
    keygen::{GeneratedApiKey, generate},
    sessions::{duration::ExpiresIn, public_key::CompressedPublicKey},
};

// The identity service registers tk under this client id.
const CLIENT_ID: &str = "tk";
const GRANT_DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";
// RFC 8628 Section 3.5: back off by five seconds on slow_down.
const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);
const DEFAULT_INTERVAL: Duration = Duration::from_secs(5);

pub(crate) struct Approved {
    pub(crate) key_file: PathBuf,
    pub(crate) public_key: CompressedPublicKey,
    pub(crate) organization_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) expires_in: Duration,
}

#[derive(Deserialize)]
struct DeviceCode {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: Option<u64>,
}

#[derive(Deserialize)]
struct Collected {
    user_id: Uuid,
    organization_id: Uuid,
    expires_in: u64,
}

#[derive(Deserialize)]
struct OAuthError {
    error: String,
}

pub(crate) async fn login(issuer: &ApiBaseUrl, expires_in: Option<ExpiresIn>) -> Result<Approved> {
    let GeneratedApiKey { public_key, path } = generate(None).await?;
    match approve(issuer, expires_in, &public_key, &path).await {
        Ok(Collected {
            user_id,
            organization_id,
            expires_in,
        }) => Ok(Approved {
            key_file: path,
            public_key,
            organization_id,
            user_id,
            expires_in: Duration::from_secs(expires_in),
        }),
        Err(error) => {
            if let Err(remove_error) = tokio::fs::remove_file(&path).await {
                debug!(%remove_error, "generated key file was not removed");
            }
            Err(error)
        }
    }
}

async fn approve(
    issuer: &ApiBaseUrl,
    expires_in: Option<ExpiresIn>,
    public_key: &CompressedPublicKey,
    key_file: &Path,
) -> Result<Collected> {
    let issuer = issuer.as_str().trim_end_matches('/');
    let signing_key = {
        let private = Zeroizing::new(read_key(key_file).await?.private_key());
        SigningKey::from_slice(&private).context("load the generated session key")?
    };
    let http = http_client()?;

    let mut form = vec![
        ("client_id", CLIENT_ID.to_owned()),
        ("public_key", public_key.to_string()),
    ];
    if let Some(expires_in) = expires_in {
        form.push((
            "session_expiration_seconds",
            expires_in.seconds().to_string(),
        ));
    }
    let code: DeviceCode = {
        let response = http
            .post(format!("{issuer}/device/code"))
            .form(&form)
            .send()
            .await
            .context("ask the identity service for a device code")?;
        read_json(response).await?
    };

    show_code(&code, public_key);

    let token_url = format!("{issuer}/token");
    let deadline = Instant::now() + Duration::from_secs(code.expires_in);
    let mut interval = code.interval.map_or(DEFAULT_INTERVAL, Duration::from_secs);
    loop {
        sleep(interval).await;
        if Instant::now() >= deadline {
            return Err(DeviceLoginRefused("expired before anyone approved it".into()).into());
        }
        let response = http
            .post(&token_url)
            .header("DPoP", dpop_proof(&signing_key, &token_url)?)
            .form(&[
                ("grant_type", GRANT_DEVICE_CODE),
                ("client_id", CLIENT_ID),
                ("device_code", code.device_code.as_str()),
            ])
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            // RFC 8628 Section 3.5: keep polling through a transport failure.
            Err(error) if error.is_timeout() || error.is_connect() => {
                debug!(%error, "device token poll failed; polling again");
                continue;
            }
            Err(error) => return Err(error).context("poll the identity service"),
        };
        if response.status() == StatusCode::BAD_REQUEST {
            let body = response.text().await.context("read the poll response")?;
            let OAuthError { error } = serde_json::from_str(&body)
                .map_err(|error| Malformed::new("malformed device token error", error))?;
            match error.as_str() {
                "authorization_pending" => continue,
                "slow_down" => {
                    interval += SLOW_DOWN_STEP;
                    continue;
                }
                "access_denied" => {
                    return Err(DeviceLoginRefused("was denied in the dashboard".into()).into());
                }
                "expired_token" => {
                    return Err(
                        DeviceLoginRefused("expired before anyone approved it".into()).into(),
                    );
                }
                _ => return Err(UnexpectedHttpStatus { status: 400, body }.into()),
            }
        }
        return read_json(response).await;
    }
}

async fn read_json<T: for<'de> Deserialize<'de>>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    let body = response
        .text()
        .await
        .context("read the identity service response")?;
    if !status.is_success() {
        return Err(UnexpectedHttpStatus {
            status: status.as_u16(),
            body,
        }
        .into());
    }
    serde_json::from_str(&body)
        .map_err(|error| Malformed::new("malformed identity service response", error).into())
}

// stdout carries the command's JSON record, so the code goes to stderr,
// which a person running the command watches.
fn show_code(code: &DeviceCode, public_key: &CompressedPublicKey) {
    let fingerprint = {
        let key = public_key.to_string();
        format!("{}…{}", &key[..8], &key[key.len() - 8..])
    };
    let mut stderr = io::stderr();
    let message = format!(
        r#"Open {} and enter this code:

    {}

Session key: {fingerprint}
Only approve if you started this sign-in. Waiting for approval…
"#,
        code.verification_uri, code.user_code
    );
    if let Err(error) = stderr.write_all(message.as_bytes()) {
        debug!(%error, "device code was not written to stderr");
    }
}

fn dpop_proof(key: &SigningKey, url: &str) -> Result<String> {
    let point = key.verifying_key().to_encoded_point(false);
    // An uncompressed SEC1 point is 0x04 || x || y, 32 bytes each.
    let (x, y) = point.as_bytes()[1..].split_at(32);
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {"kty": "EC", "crv": "P-256", "x": URL_SAFE_NO_PAD.encode(x), "y": URL_SAFE_NO_PAD.encode(y)},
    });
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("read the clock")?
        .as_secs();
    let claims = json!({
        "jti": Uuid::new_v4(),
        "htm": "POST",
        "htu": url,
        "iat": issued_at,
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
    );
    let signature: Signature = key.sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{VerifyingKey, signature::Verifier};
    use serde_json::Value;

    use super::*;

    #[test]
    fn dpop_proofs_verify_under_their_embedded_key() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let proof = dpop_proof(&key, "https://id.example.com/login/token").expect("proof");

        let parts: Vec<&str> = proof.split('.').collect();
        let [header, claims, signature] = parts.as_slice() else {
            panic!("a compact JWS has three parts: {proof}");
        };
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).expect("header")).expect("json");
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims).expect("claims")).expect("json");

        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(claims["htm"], "POST");
        assert_eq!(claims["htu"], "https://id.example.com/login/token");

        let point = key.verifying_key().to_encoded_point(false);
        assert_eq!(
            header["jwk"],
            json!({"kty": "EC", "crv": "P-256", "x": URL_SAFE_NO_PAD.encode(point.x().expect("x")), "y": URL_SAFE_NO_PAD.encode(point.y().expect("y"))})
        );

        let signature =
            Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature).expect("signature"))
                .expect("r || s");
        let signing_input = proof.rsplit_once('.').expect("dot").0;
        VerifyingKey::from(&key)
            .verify(signing_input.as_bytes(), &signature)
            .expect("the proof verifies under its key");
    }
}
