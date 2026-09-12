//! Signs OpenPGP digests through Turnkey sign raw payload.

use anyhow::{Context, Result};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_auth::openpgp::entity::{EcdsaSignature, SignDigest, SignDigestFuture};
use turnkey_auth::openpgp::key::UncompressedPoint;
use turnkey_client::generated::{
    SignRawPayloadIntentV2, SignRawPayloadResult,
    immutable::common::v1::{HashFunction, PayloadEncoding},
};
use turnkey_client::{ActivityResult, TurnkeyClient};

use crate::errors::{ActivityError, ActivityErrorKind};

/// The digest is already the value OpenPGP signs, so the hash function is
/// [`HashFunction::NoOp`].
pub struct TurnkeySigner<'c> {
    client: &'c TurnkeyClient<TurnkeyP256ApiKey>,
    org_id: &'c str,
}

impl<'c> TurnkeySigner<'c> {
    pub fn new(client: &'c TurnkeyClient<TurnkeyP256ApiKey>, org_id: &'c str) -> Self {
        Self { client, org_id }
    }
}

fn scalar(value: &str, field: &str) -> Result<[u8; 32]> {
    let malformed = |reason: &str| {
        ActivityError::new(
            ActivityErrorKind::MalformedResponse,
            format!("{field} is {reason}"),
        )
    };
    let bytes = hex::decode(value).map_err(|error| malformed("not hex").with_source(error))?;
    bytes
        .try_into()
        .map_err(|_| malformed("not 32 bytes").into())
}

impl SignDigest for TurnkeySigner<'_> {
    fn sign_digest<'a>(
        &'a self,
        signer: UncompressedPoint,
        digest: [u8; 32],
    ) -> SignDigestFuture<'a> {
        Box::pin(async move {
            let activity = self
                .client
                .sign_raw_payload(
                    self.org_id.to_string(),
                    self.client.current_timestamp(),
                    SignRawPayloadIntentV2 {
                        sign_with: hex::encode(signer.as_bytes()),
                        payload: hex::encode(digest),
                        encoding: PayloadEncoding::Hexadecimal,
                        hash_function: HashFunction::NoOp,
                    },
                )
                .await
                .map_err(anyhow::Error::new)
                .context("sign the OpenPGP digest")?;
            let ActivityResult {
                result,
                activity_id: _,
                status: _,
                app_proofs: _,
            } = activity;
            let SignRawPayloadResult { r, s, v: _ } = result;
            Ok(EcdsaSignature {
                r: scalar(&r, "signRawPayloadResult.r")?,
                s: scalar(&s, "signRawPayloadResult.s")?,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_or_non_hex_scalar_is_a_malformed_response_naming_the_field() {
        for (value, field, message, chain_len) in [
            (
                "00".to_string(),
                "signRawPayloadResult.r",
                "signRawPayloadResult.r is not 32 bytes",
                1,
            ),
            (
                "z".repeat(64),
                "signRawPayloadResult.s",
                "signRawPayloadResult.s is not hex",
                2,
            ),
        ] {
            let error = scalar(&value, field).expect_err("a bad scalar should fail");
            let activity = error
                .downcast_ref::<ActivityError>()
                .expect("the error should be an ActivityError");
            assert_eq!(activity.kind(), ActivityErrorKind::MalformedResponse);
            assert_eq!(activity.to_string(), message);
            assert_eq!(
                error.chain().count(),
                chain_len,
                "the cause stays in the chain"
            );
        }
    }
}
