use std::io::{self, IsTerminal, Write};

use ::yubikey::{
    Context, Error as PivError, PinPolicy, Serial, TouchPolicy, YubiKey,
    piv::{self, AlgorithmId, ManagementAlgorithmId, Origin, SlotId, SlotMetadata},
};
use anyhow::{Context as _, Result};
use p256::{
    PublicKey,
    ecdsa::{DerSignature, VerifyingKey, signature::Verifier},
    elliptic_curve::sec1::ToEncodedPoint,
};
use sha2::{Digest, Sha256};

use super::{PivSlot, YubiKeyCredential, YubiKeySerial};
use crate::{errors::InvalidInput, sessions::public_key::CompressedPublicKey};

#[derive(Debug, thiserror::Error)]
enum SelectionError {
    #[error("no YubiKey is connected")]
    NoneConnected,
    #[error("YubiKey {0} is not connected")]
    NotConnected(YubiKeySerial),
    #[error("several YubiKeys are connected: {}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "))]
    Ambiguous(Vec<YubiKeySerial>),
}

pub(super) fn discover(serial: Option<YubiKeySerial>, slot: PivSlot) -> Result<YubiKeyCredential> {
    let serial = match serial {
        Some(serial) => serial,
        None => sole_connected()?,
    };
    let mut yubikey = open(serial)?;
    let metadata = match piv::metadata(&mut yubikey, slot_id(slot)?) {
        Ok(metadata) => metadata,
        Err(PivError::NotSupported) => {
            return Err(InvalidInput(format!(
                "YubiKey {serial} cannot report slot metadata; tk needs firmware 5.2.3 or later"
            ))
            .into());
        }
        // `yubikey` reports PIV status 0x6a88, referenced data not found, as a
        // generic error.
        Err(PivError::GenericError) => {
            return Err(
                InvalidInput(format!("slot {slot} on YubiKey {serial} holds no key")).into(),
            );
        }
        Err(error) => {
            return Err(error).with_context(|| format!("read slot {slot} on YubiKey {serial}"));
        }
    };
    let public_key = signing_key(slot, metadata)?;
    Ok(YubiKeyCredential {
        serial,
        slot,
        public_key,
    })
}

pub(super) fn sign(credential: &YubiKeyCredential, message: &[u8]) -> Result<Vec<u8>> {
    let YubiKeyCredential {
        serial,
        slot,
        public_key,
    } = credential;
    let verifying_key = VerifyingKey::from_sec1_bytes(&hex::decode(public_key.to_string())?)
        .context("decode the profile's YubiKey public key")?;
    let mut yubikey = open(*serial)?;
    if io::stderr().is_terminal() {
        let _ = writeln!(
            io::stderr(),
            "Touch YubiKey {serial} if it is flashing to authorize the Turnkey request."
        );
    }
    let signature = piv::sign_data(
        &mut yubikey,
        &Sha256::digest(message),
        AlgorithmId::EccP256,
        slot_id(*slot)?,
    )
    .with_context(|| {
        format!("slot {slot} on YubiKey {serial} did not sign; touch the device while it flashes")
    })?;
    let signature = DerSignature::from_bytes(&signature).with_context(|| {
        format!("slot {slot} on YubiKey {serial} returned a malformed signature")
    })?;
    verifying_key.verify(message, &signature).with_context(|| {
        format!("slot {slot} on YubiKey {serial} no longer holds key {public_key}")
    })?;
    Ok(signature.as_bytes().to_vec())
}

fn sole_connected() -> Result<YubiKeySerial> {
    let mut context = Context::open().context("list smart card readers")?;
    let mut connected = Vec::new();
    for reader in context.iter().context("list smart card readers")? {
        match reader.open() {
            Ok(yubikey) => connected.push(YubiKeySerial(yubikey.serial().0)),
            // A smart card without the PIV applet is not a YubiKey tk can use.
            Err(PivError::AppletNotFound { .. }) => {}
            Err(error) => {
                return Err(error).with_context(|| format!("open reader {}", reader.name()));
            }
        }
    }
    match connected.as_slice() {
        [] => Err(SelectionError::NoneConnected.into()),
        [sole] => Ok(*sole),
        _ => Err(SelectionError::Ambiguous(connected).into()),
    }
}

fn open(serial: YubiKeySerial) -> Result<YubiKey> {
    YubiKey::open_by_serial(Serial(serial.0)).map_err(|error| match error {
        PivError::NotFound => SelectionError::NotConnected(serial).into(),
        error => anyhow::Error::new(error).context(format!("open YubiKey {serial}")),
    })
}

fn slot_id(slot: PivSlot) -> Result<SlotId> {
    SlotId::try_from(slot.0).with_context(|| format!("PIV slot {slot}"))
}

fn signing_key(slot: PivSlot, metadata: SlotMetadata) -> Result<CompressedPublicKey> {
    let SlotMetadata {
        algorithm,
        policy,
        origin,
        public,
        default: _,
        retries: _,
    } = metadata;
    if algorithm != ManagementAlgorithmId::Asymmetric(AlgorithmId::EccP256) {
        return Err(InvalidInput(format!(
            "slot {slot} holds a key of type {algorithm:?}, not the P256 key Turnkey requires"
        ))
        .into());
    }
    if origin != Some(Origin::Generated) {
        return Err(InvalidInput(format!(
            "slot {slot} holds a key that was not generated on the YubiKey, so a copy may exist elsewhere"
        ))
        .into());
    }
    match policy {
        Some((PinPolicy::Never, TouchPolicy::Always | TouchPolicy::Cached)) => {}
        Some((PinPolicy::Never, touch)) => {
            return Err(InvalidInput(format!(
                "slot {slot} has touch policy {touch:?}; tk requires touch policy always or cached"
            ))
            .into());
        }
        Some((pin, _)) => {
            return Err(InvalidInput(format!(
                "slot {slot} has PIN policy {pin:?}; tk never prompts for a PIV PIN and requires PIN policy never"
            ))
            .into());
        }
        None => {
            return Err(InvalidInput(format!(
                "slot {slot} did not report its PIN and touch policies"
            ))
            .into());
        }
    }
    let Some(public) = public else {
        return Err(InvalidInput(format!("slot {slot} did not report its public key")).into());
    };
    let point = PublicKey::from_sec1_bytes(public.subject_public_key.raw_bytes())
        .with_context(|| format!("decode the public key in slot {slot}"))?
        .to_encoded_point(true);
    Ok(hex::encode(point.as_bytes()).parse()?)
}

#[cfg(test)]
mod tests {
    use der::Decode;
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;

    use super::*;

    const SLOT: PivSlot = PivSlot(0x9a);
    // The DER prefix of a P256 SubjectPublicKeyInfo, ahead of its uncompressed point.
    const P256_SPKI_PREFIX: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

    fn metadata(
        algorithm: AlgorithmId,
        policy: (PinPolicy, TouchPolicy),
        origin: Origin,
        key: &SigningKey,
    ) -> SlotMetadata {
        let point = key.verifying_key().to_encoded_point(false);
        let spki = hex::decode(format!(
            "{P256_SPKI_PREFIX}{}",
            hex::encode(point.as_bytes())
        ))
        .unwrap();
        SlotMetadata {
            algorithm: ManagementAlgorithmId::Asymmetric(algorithm),
            policy: Some(policy),
            origin: Some(origin),
            public: Some(Decode::from_der(&spki).unwrap()),
            default: None,
            retries: None,
        }
    }

    fn refusal(metadata: SlotMetadata) -> String {
        let error = signing_key(SLOT, metadata).unwrap_err();
        assert!(error.downcast_ref::<InvalidInput>().is_some(), "{error:#}");
        error.to_string()
    }

    #[test]
    fn a_generated_touch_only_p256_key_is_accepted_compressed() {
        let key = SigningKey::random(&mut OsRng);
        let expected = hex::encode(key.verifying_key().to_encoded_point(true).as_bytes());
        for touch in [TouchPolicy::Always, TouchPolicy::Cached] {
            let accepted = signing_key(
                SLOT,
                metadata(
                    AlgorithmId::EccP256,
                    (PinPolicy::Never, touch),
                    Origin::Generated,
                    &key,
                ),
            )
            .unwrap();
            assert_eq!(accepted.to_string(), expected);
        }
    }

    #[test]
    fn keys_that_skip_the_touch_need_a_pin_or_were_imported_are_refused() {
        let key = SigningKey::random(&mut OsRng);
        let touch_only = (PinPolicy::Never, TouchPolicy::Always);
        assert_eq!(
            refusal(metadata(
                AlgorithmId::EccP256,
                (PinPolicy::Never, TouchPolicy::Never),
                Origin::Generated,
                &key
            )),
            "slot 9a has touch policy Never; tk requires touch policy always or cached"
        );
        assert_eq!(
            refusal(metadata(
                AlgorithmId::EccP256,
                (PinPolicy::Once, TouchPolicy::Always),
                Origin::Generated,
                &key
            )),
            "slot 9a has PIN policy Once; tk never prompts for a PIV PIN and requires PIN policy never"
        );
        assert_eq!(
            refusal(metadata(
                AlgorithmId::EccP256,
                touch_only,
                Origin::Imported,
                &key
            )),
            "slot 9a holds a key that was not generated on the YubiKey, so a copy may exist elsewhere"
        );
        assert_eq!(
            refusal(metadata(
                AlgorithmId::EccP384,
                touch_only,
                Origin::Generated,
                &key
            )),
            "slot 9a holds a key of type Asymmetric(EccP384), not the P256 key Turnkey requires"
        );
    }
}
