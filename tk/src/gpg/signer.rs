//! The bridge between the OpenPGP byte layer and Turnkey: it turns a digest
//! into the ECDSA scalars the packet framing needs.

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

/// Signs digests through Turnkey sign raw payload.
///
/// The digest is already the value OpenPGP signs, so the hash function is
/// [`HashFunction::NoOp`]: the server must sign the bytes as given. Hashing
/// them again would produce a signature no verifier accepts.
pub struct TurnkeySigner<'c> {
    client: &'c TurnkeyClient<TurnkeyP256ApiKey>,
    org_id: &'c str,
}

impl<'c> TurnkeySigner<'c> {
    /// Binds a signer to an already built client and the organization that
    /// owns the wallet.
    pub fn new(client: &'c TurnkeyClient<TurnkeyP256ApiKey>, org_id: &'c str) -> Self {
        Self { client, org_id }
    }
}

/// Decodes one 32 byte big endian scalar from the hex the API returns.
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
    fn a_short_scalar_is_a_malformed_response_naming_the_field() {
        let error = scalar("00", "signRawPayloadResult.r").expect_err("a short r should fail");
        let activity = error
            .downcast_ref::<ActivityError>()
            .expect("the error should be an ActivityError");
        assert_eq!(activity.kind(), ActivityErrorKind::MalformedResponse);
        assert_eq!(
            activity.to_string(),
            "signRawPayloadResult.r is not 32 bytes"
        );
    }

    #[test]
    fn a_non_hex_scalar_is_a_malformed_response_naming_the_field() {
        let error =
            scalar(&"z".repeat(64), "signRawPayloadResult.s").expect_err("a non hex s should fail");
        let activity = error
            .downcast_ref::<ActivityError>()
            .expect("the error should be an ActivityError");
        assert_eq!(activity.kind(), ActivityErrorKind::MalformedResponse);
        assert_eq!(activity.to_string(), "signRawPayloadResult.s is not hex");
        assert_eq!(
            error.chain().count(),
            2,
            "the decode failure stays in the chain"
        );
    }

    #[test]
    fn a_32_byte_scalar_decodes() {
        assert_eq!(
            scalar(&"ab".repeat(32), "signRawPayloadResult.r").expect("32 bytes should decode"),
            [0xab; 32]
        );
    }
}
