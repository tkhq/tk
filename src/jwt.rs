//! Compact ES256 JWTs signed by a profile's P-256 key: proofs of possession and OAuth client assertions.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{Value, json};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use uuid::Uuid;
use zeroize::Zeroizing;

// The identity service refuses a client assertion that lives longer than five minutes.
const ASSERTION_LIFETIME_SECS: u64 = 60;

pub(crate) fn signing_key(key: &TurnkeyP256ApiKey) -> Result<SigningKey> {
    let private = Zeroizing::new(key.private_key());
    SigningKey::from_slice(&private).context("load the P-256 signing key")
}

fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("read the clock")?
        .as_secs())
}

fn sign(key: &SigningKey, header: &Value, claims: &Value) -> Result<String> {
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?)
    );
    let signature: Signature = key.sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

pub(crate) fn dpop_proof(key: &SigningKey, url: &str, nonce: Option<&str>) -> Result<String> {
    let point = key.verifying_key().to_encoded_point(false);
    // An uncompressed SEC1 point is 0x04 || x || y, 32 bytes each.
    let (x, y) = point.as_bytes()[1..].split_at(32);
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {"kty": "EC", "crv": "P-256", "x": URL_SAFE_NO_PAD.encode(x), "y": URL_SAFE_NO_PAD.encode(y)},
    });
    let mut claims = json!({
        "jti": Uuid::new_v4(),
        "htm": "POST",
        "htu": url,
        "iat": now()?,
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }
    sign(key, &header, &claims)
}

pub(crate) fn client_assertion(
    key: &SigningKey,
    client_id: &str,
    audience: &str,
) -> Result<String> {
    let issued_at = now()?;
    sign(
        key,
        &json!({"alg": "ES256"}),
        &json!({
            "iss": client_id,
            "sub": client_id,
            "aud": audience,
            "jti": Uuid::new_v4(),
            "iat": issued_at,
            "exp": issued_at + ASSERTION_LIFETIME_SECS,
        }),
    )
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{VerifyingKey, signature::Verifier};

    use super::*;

    fn decode(token: &str) -> (Value, Value) {
        let parts: Vec<&str> = token.split('.').collect();
        let [header, claims, signature] = parts.as_slice() else {
            panic!("a compact JWS has three parts: {token}");
        };
        assert_eq!(URL_SAFE_NO_PAD.decode(signature).unwrap().len(), 64);
        (
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap(),
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims).unwrap()).unwrap(),
        )
    }

    fn verifies(key: &SigningKey, token: &str) {
        let (signing_input, signature) = token.rsplit_once('.').unwrap();
        let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature).unwrap()).unwrap();
        VerifyingKey::from(key)
            .verify(signing_input.as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn dpop_proofs_carry_their_key_and_nonce() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let proof = dpop_proof(&key, "https://id.example.com/login/token", Some("n-1")).unwrap();
        let (header, claims) = decode(&proof);

        let point = key.verifying_key().to_encoded_point(false);
        let (x, y) = point.as_bytes()[1..].split_at(32);
        assert_eq!(
            header,
            json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": {"kty": "EC", "crv": "P-256", "x": URL_SAFE_NO_PAD.encode(x), "y": URL_SAFE_NO_PAD.encode(y)}})
        );
        assert_eq!(claims["htm"], "POST");
        assert_eq!(claims["htu"], "https://id.example.com/login/token");
        assert_eq!(claims["nonce"], "n-1");
        verifies(&key, &proof);

        let (_, claims) = decode(&dpop_proof(&key, "https://x", None).unwrap());
        assert!(claims.get("nonce").is_none());
    }

    #[test]
    fn client_assertions_name_the_client_and_the_issuer() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let assertion = client_assertion(
            &key,
            "urn:turnkey:user:u-1",
            "https://id.example.com/t/parent",
        )
        .unwrap();
        let (header, claims) = decode(&assertion);

        assert_eq!(header, json!({"alg": "ES256"}));
        assert_eq!(claims["iss"], "urn:turnkey:user:u-1");
        assert_eq!(claims["sub"], "urn:turnkey:user:u-1");
        assert_eq!(claims["aud"], "https://id.example.com/t/parent");
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
            ASSERTION_LIFETIME_SECS
        );
        verifies(&key, &assertion);
    }
}
