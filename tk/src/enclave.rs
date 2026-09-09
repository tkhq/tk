//! Secrets extensions for Turnkey enclave encryption.
//!
//! This is the tk port of the `enclave_encrypt` client additions from
//! tkhq/rust-sdk#274: encrypting arbitrary secret bytes to an authenticated
//! Secrets ingress target and decrypting export bundles. Secrets accept only
//! v1 messages, whose signed data binds the organization; legacy (v0)
//! messages without organization binding are rejected. Secrets targets do not
//! require a user ID.

use anyhow::{Context, Result, bail, ensure};
use hpke::{Deserializable, Kem as KemTrait, OpModeS, Serializable};
use p256::{
    PublicKey,
    ecdsa::{DerSignature, VerifyingKey, signature::Verifier},
};
use rand_core::OsRng;
use serde::Deserialize;
use serde_json::json;
use turnkey_enclave_encrypt::{P256Public, QuorumPublicKey, ServerTargetMsgV1};

/// HPKE configuration; must match `turnkey_enclave_encrypt`'s server side.
type Kem = hpke::kem::DhP256HkdfSha256;
type Aead = hpke::aead::AesGcm256;
type Kdf = hpke::kdf::HkdfSha256;
const TURNKEY_HPKE_INFO: &[u8] = b"turnkey_hpke";
const DATA_VERSION: &str = "v1.0.0";

/// The signed data object of a Secrets ingress target: the enclave target key
/// bound to an organization. Unlike key-import targets, no user ID is bound.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretTargetData {
    target_public: P256Public,
    organization_id: String,
}

/// Verifies a v1 message's signature against the trusted quorum key and
/// returns its signed data bytes.
fn verified_data(
    quorum: &QuorumPublicKey,
    version: &str,
    data: &[u8],
    data_signature: &[u8],
    enclave_quorum_public: &P256Public,
) -> Result<()> {
    ensure!(
        version == DATA_VERSION,
        "Secrets require v1 enclave messages with organization binding"
    );
    let public = PublicKey::from_sec1_bytes(&**enclave_quorum_public)
        .map_err(|_| anyhow::anyhow!("invalid enclave quorum public key"))?;
    let verifying_key = VerifyingKey::from(public);
    ensure!(
        verifying_key == quorum.verifying_key().map_err(anyhow::Error::new)?,
        "enclave quorum public key does not match the trusted quorum key"
    );
    let signature = DerSignature::try_from(data_signature)
        .map_err(|_| anyhow::anyhow!("invalid enclave message signature encoding"))?;
    verifying_key
        .verify(data, &signature)
        .map_err(|_| anyhow::anyhow!("enclave message signature verification failed"))?;
    Ok(())
}

/// Encrypts arbitrary secret bytes to a signed Secrets ingress target.
/// Returns the serialized encrypted payload and its uncompressed target
/// public key. Only v1 bundles signed by the trusted quorum key and bound to
/// `organization_id` are accepted.
pub fn encrypt_secret_with_bundle(
    quorum: &QuorumPublicKey,
    plaintext: &[u8],
    bundle: &str,
    organization_id: &str,
) -> Result<(String, String)> {
    let msg: ServerTargetMsgV1 =
        serde_json::from_str(bundle).map_err(|_| anyhow::anyhow!("invalid target bundle"))?;
    verified_data(
        quorum,
        &msg.version,
        &msg.data,
        &msg.data_signature,
        &msg.enclave_quorum_public,
    )?;
    let data: SecretTargetData = serde_json::from_slice(&msg.data)
        .map_err(|_| anyhow::anyhow!("invalid target bundle data"))?;
    ensure!(
        data.organization_id == organization_id,
        "target bundle is bound to a different organization"
    );
    let receiver = <Kem as KemTrait>::PublicKey::from_bytes(&*data.target_public)
        .map_err(|_| anyhow::anyhow!("invalid enclave target public key"))?;
    let (encapped_public, mut sender) = hpke::setup_sender::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &receiver,
        TURNKEY_HPKE_INFO,
        &mut OsRng,
    )
    .map_err(|_| anyhow::anyhow!("could not set up encryption to the enclave target"))?;
    let aad: Vec<u8> = encapped_public
        .to_bytes()
        .iter()
        .chain(receiver.to_bytes().iter())
        .copied()
        .collect();
    let ciphertext = sender
        .seal(plaintext, &aad)
        .map_err(|_| anyhow::anyhow!("could not encrypt the secret"))?;
    let payload = json!({
        "encappedPublic": hex::encode(encapped_public.to_bytes()),
        "ciphertext": hex::encode(ciphertext),
    })
    .to_string();
    Ok((payload, hex::encode(*data.target_public)))
}

/// A resumable Secrets export recipient derived from persisted key material.
pub struct SecretRecipient {
    client: turnkey_enclave_encrypt::client::EnclaveEncryptClient,
}

impl SecretRecipient {
    /// Derives the recipient key pair from input key material. The same ikm
    /// always derives the same target, which is what makes export recovery
    /// possible; the pair must still be used for a single decryption only.
    pub fn from_ikm(ikm: &[u8], quorum: &QuorumPublicKey) -> Result<Self> {
        ensure!(ikm.len() == 32, "invalid recovery key size");
        let (private, public) = Kem::derive_keypair(ikm);
        Ok(Self {
            client:
                turnkey_enclave_encrypt::client::EnclaveEncryptClient::from_enclave_auth_key_and_target_key(
                    quorum.verifying_key().map_err(anyhow::Error::new)?,
                    public,
                    private,
                ),
        })
    }

    /// The target public key for `EXPORT_SECRETS` activity parameters,
    /// encoded as uncompressed SEC1 hex.
    pub fn target_public_key(&self) -> Result<String> {
        Ok(hex::encode(
            self.client.target_bytes().map_err(anyhow::Error::new)?,
        ))
    }

    /// Decrypts arbitrary secret bytes from an authenticated,
    /// organization-bound v1 bundle. Legacy bundles without organization
    /// binding are not accepted for Secrets.
    pub fn decrypt_secret(&mut self, bundle: &str, organization_id: &str) -> Result<Vec<u8>> {
        let header: serde_json::Value =
            serde_json::from_str(bundle).context("invalid export bundle")?;
        if header["version"].as_str() != Some(DATA_VERSION) {
            bail!("Secrets require v1 enclave messages with organization binding");
        }
        self.client
            .decrypt(bundle.as_bytes(), organization_id)
            .context("could not verify and decrypt the export bundle")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use rand_core::RngCore;
    use turnkey_enclave_encrypt::server::EnclaveEncryptServer;

    /// A test quorum: one random signing key doubled into the two-part quorum
    /// public key layout (encryption key || signing key).
    pub(crate) fn quorum() -> (SigningKey, QuorumPublicKey) {
        let key = SigningKey::random(&mut OsRng);
        let public = key.verifying_key().to_encoded_point(false);
        let bytes = [public.as_bytes(), public.as_bytes()].concat();
        (key, QuorumPublicKey::from_bytes(bytes).unwrap())
    }

    #[test]
    fn secrets_import_roundtrip_and_authenticated_metadata() {
        let (signing, quorum_public) = quorum();
        let enclave = EnclaveEncryptServer::from_enclave_auth_key(
            signing,
            "org-id".into(),
            Some("unused-user".into()),
        );
        let mut bundle = enclave.publish_target().unwrap();
        let encoded = serde_json::to_string(&bundle).unwrap();
        let plaintext = b"\x00\xffsecret\n";
        let (payload, target) =
            encrypt_secret_with_bundle(&quorum_public, plaintext, &encoded, "org-id").unwrap();
        let data: serde_json::Value = serde_json::from_slice(&bundle.data).unwrap();
        assert_eq!(target, data["targetPublic"].as_str().unwrap());
        assert_eq!(
            enclave
                .into_recv()
                .decrypt(&serde_json::from_str(&payload).unwrap())
                .unwrap(),
            plaintext
        );
        assert!(
            encrypt_secret_with_bundle(&quorum_public, plaintext, &encoded, "wrong-org").is_err()
        );
        assert!(
            encrypt_secret_with_bundle(
                &QuorumPublicKey::production_signer(),
                plaintext,
                &encoded,
                "org-id"
            )
            .is_err()
        );
        bundle.data[0] ^= 1;
        assert!(
            encrypt_secret_with_bundle(
                &quorum_public,
                plaintext,
                &serde_json::to_string(&bundle).unwrap(),
                "org-id"
            )
            .is_err()
        );
        bundle.version = "v2.0.0".into();
        assert!(
            encrypt_secret_with_bundle(
                &quorum_public,
                plaintext,
                &serde_json::to_string(&bundle).unwrap(),
                "org-id"
            )
            .is_err()
        );
        assert!(
            encrypt_secret_with_bundle(
                &quorum_public,
                plaintext,
                r#"{"targetPublic":"00"}"#,
                "org-id"
            )
            .is_err()
        );
    }

    #[test]
    fn secrets_export_preserves_bytes_and_restores_recipient() {
        for plaintext in [Vec::new(), vec![0, 255, 10], vec![42; 65536]] {
            let (signing, quorum_public) = quorum();
            let mut ikm = [0u8; 32];
            OsRng.fill_bytes(&mut ikm);
            let original = SecretRecipient::from_ikm(&ikm, &quorum_public).unwrap();
            let target = original.target_public_key().unwrap();
            let enclave =
                EnclaveEncryptServer::from_enclave_auth_key(signing, "org-id".into(), None);
            let bundle = enclave
                .encrypt(
                    &hex::decode(&target).unwrap().try_into().unwrap(),
                    &plaintext,
                )
                .unwrap();
            let encoded = serde_json::to_string(&bundle).unwrap();
            let mut resumed = SecretRecipient::from_ikm(&ikm, &quorum_public).unwrap();
            assert_eq!(resumed.target_public_key().unwrap(), target);
            assert!(resumed.decrypt_secret(&encoded, "wrong-org").is_err());
            assert_eq!(
                resumed.decrypt_secret(&encoded, "org-id").unwrap(),
                plaintext
            );
            // A recipient may decrypt only once.
            assert!(resumed.decrypt_secret(&encoded, "org-id").is_err());
            // A different quorum key must not verify the bundle.
            assert!(
                SecretRecipient::from_ikm(&ikm, &QuorumPublicKey::production_signer())
                    .unwrap()
                    .decrypt_secret(&encoded, "org-id")
                    .is_err()
            );
            // Version tampering and removal are rejected before decryption.
            let mut tampered: serde_json::Value = serde_json::from_str(&encoded).unwrap();
            tampered["version"] = "v2.0.0".into();
            assert!(
                SecretRecipient::from_ikm(&ikm, &quorum_public)
                    .unwrap()
                    .decrypt_secret(&tampered.to_string(), "org-id")
                    .is_err()
            );
            tampered.as_object_mut().unwrap().remove("version");
            assert!(
                SecretRecipient::from_ikm(&ikm, &quorum_public)
                    .unwrap()
                    .decrypt_secret(&tampered.to_string(), "org-id")
                    .is_err()
            );
            // Corrupted signed data fails signature verification.
            let mut corrupted: serde_json::Value = serde_json::from_str(&encoded).unwrap();
            let mut data = hex::decode(corrupted["data"].as_str().unwrap()).unwrap();
            data[0] ^= 1;
            corrupted["data"] = hex::encode(data).into();
            assert!(
                SecretRecipient::from_ikm(&ikm, &quorum_public)
                    .unwrap()
                    .decrypt_secret(&corrupted.to_string(), "org-id")
                    .is_err()
            );
        }
    }

    #[test]
    fn secrets_reject_authenticated_invalid_targets_and_corrupted_ciphertext() {
        use p256::ecdsa::signature::Signer;
        let (signing, quorum_public) = quorum();
        let enclave = EnclaveEncryptServer::from_enclave_auth_key(
            signing.clone(),
            "org-id".into(),
            Some("unused-user".into()),
        );
        // A correctly signed bundle whose target key is not a valid point.
        let mut ingress = enclave.publish_target().unwrap();
        let mut data: serde_json::Value = serde_json::from_slice(&ingress.data).unwrap();
        data["targetPublic"] = hex::encode([0u8; 65]).into();
        ingress.data = serde_json::to_vec(&data).unwrap();
        let signature: p256::ecdsa::Signature = signing.sign(&ingress.data);
        ingress.data_signature = signature.to_der().to_bytes().to_vec().into();
        assert!(
            encrypt_secret_with_bundle(
                &quorum_public,
                b"synthetic",
                &serde_json::to_string(&ingress).unwrap(),
                "org-id"
            )
            .is_err()
        );

        // A correctly signed export bundle with corrupted ciphertext.
        let ikm = [7u8; 32];
        let mut recipient = SecretRecipient::from_ikm(&ikm, &quorum_public).unwrap();
        let target = hex::decode(recipient.target_public_key().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let mut export =
            serde_json::to_value(enclave.encrypt(&target, b"synthetic").unwrap()).unwrap();
        let mut data: serde_json::Value =
            serde_json::from_slice(&hex::decode(export["data"].as_str().unwrap()).unwrap())
                .unwrap();
        let mut ciphertext = hex::decode(data["ciphertext"].as_str().unwrap()).unwrap();
        ciphertext[0] ^= 1;
        data["ciphertext"] = hex::encode(ciphertext).into();
        let data = serde_json::to_vec(&data).unwrap();
        let signature: p256::ecdsa::Signature = signing.sign(&data);
        export["data"] = hex::encode(&data).into();
        export["dataSignature"] = hex::encode(signature.to_der().to_bytes()).into();
        assert!(
            recipient
                .decrypt_secret(&export.to_string(), "org-id")
                .is_err()
        );
    }
}
