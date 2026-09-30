use std::{
    io::{self, ErrorKind},
    str::from_utf8,
};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::super::registry::SigningKeyName;
use crate::wire::openpgp::{entity::ArmoredSignature, key::Fingerprint};

const MAGIC: [u8; 4] = *b"TKGP";
const VERSION: u8 = 1;
const SIGN: u8 = 1;
const SUCCESS: u8 = 0;
const REQUEST_HEADER_LEN: usize = 12;
const RESPONSE_HEADER_LEN: usize = 14;
const FINGERPRINT_LEN: usize = 40;
pub(super) const MAX_PAYLOAD_LEN: usize = 1024 * 1024;
const MAX_KEY_LEN: usize = FINGERPRINT_LEN;
const MAX_SIGNATURE_LEN: usize = 64 * 1024;

pub(super) struct SignRequest {
    pub key: Option<SigningKeyName>,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Error)]
#[repr(u8)]
pub(super) enum Failure {
    #[error("OpenPGP agent rejected the request")]
    InvalidRequest = 1,
    #[error("OpenPGP agent does not serve the requested key")]
    KeyNotServed = 2,
    #[error("OpenPGP agent could not sign the payload")]
    SigningFailed = 3,
}

impl Failure {
    fn from_status(status: u8) -> Option<Self> {
        match status {
            status if status == Self::InvalidRequest as u8 => Some(Self::InvalidRequest),
            status if status == Self::KeyNotServed as u8 => Some(Self::KeyNotServed),
            status if status == Self::SigningFailed as u8 => Some(Self::SigningFailed),
            _ => None,
        }
    }
}

pub(super) async fn write_request(
    stream: &mut (impl AsyncWrite + Unpin),
    key: Option<&SigningKeyName>,
    payload: &[u8],
) -> io::Result<()> {
    let key = key
        .map(SigningKeyName::as_str)
        .unwrap_or_default()
        .as_bytes();
    let key_len: u16 = checked_frame_len(key.len(), MAX_KEY_LEN, "signing key is too long")?;
    let payload_len: u32 =
        checked_frame_len(payload.len(), MAX_PAYLOAD_LEN, "payload is too large")?;
    let mut header = [0_u8; REQUEST_HEADER_LEN];
    header[..6].copy_from_slice(&frame_prefix(SIGN));
    header[6..8].copy_from_slice(&key_len.to_be_bytes());
    header[8..12].copy_from_slice(&payload_len.to_be_bytes());
    stream.write_all(&header).await?;
    stream.write_all(key).await?;
    stream.write_all(payload).await?;
    // An agent that has already answered and closed leaves its response in
    // our receive buffer; macOS reports the closed peer as ENOTCONN here.
    match stream.shutdown().await {
        Err(error) if error.kind() == ErrorKind::NotConnected => Ok(()),
        result => result,
    }
}

pub(super) async fn read_request(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<SignRequest> {
    let mut header = [0_u8; REQUEST_HEADER_LEN];
    stream.read_exact(&mut header).await?;
    if header[..4] != MAGIC || header[4] != VERSION || header[5] != SIGN {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "unsupported OpenPGP agent request",
        ));
    }
    let key_len = usize::from(u16::from_be_bytes([header[6], header[7]]));
    let payload_len = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
    if key_len > MAX_KEY_LEN || payload_len > MAX_PAYLOAD_LEN {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "OpenPGP agent request exceeds its size limit",
        ));
    }
    let mut key = vec![0_u8; key_len];
    stream.read_exact(&mut key).await?;
    let key = if key.is_empty() {
        None
    } else {
        let key = String::from_utf8(key)
            .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
        Some(
            key.parse::<SigningKeyName>()
                .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?,
        )
    };
    let mut payload = vec![0_u8; payload_len];
    stream.read_exact(&mut payload).await?;
    require_eof(stream, "OpenPGP agent request has trailing data").await?;
    Ok(SignRequest { key, payload })
}

pub(super) async fn write_signature(
    stream: &mut (impl AsyncWrite + Unpin),
    signature: &ArmoredSignature,
) -> io::Result<()> {
    let fingerprint = signature.fingerprint().to_string();
    let armored = signature.as_str();
    let signature_len: u32 =
        checked_frame_len(armored.len(), MAX_SIGNATURE_LEN, "signature is too large")?;
    let mut header = [0_u8; RESPONSE_HEADER_LEN];
    header[..6].copy_from_slice(&frame_prefix(SUCCESS));
    header[6..10].copy_from_slice(&signature.created().to_be_bytes());
    header[10..14].copy_from_slice(&signature_len.to_be_bytes());
    stream.write_all(&header).await?;
    stream.write_all(fingerprint.as_bytes()).await?;
    stream.write_all(armored.as_bytes()).await?;
    stream.shutdown().await
}

pub(super) async fn write_failure(
    stream: &mut (impl AsyncWrite + Unpin),
    failure: Failure,
) -> io::Result<()> {
    let mut header = [0_u8; RESPONSE_HEADER_LEN];
    header[..6].copy_from_slice(&frame_prefix(failure as u8));
    stream.write_all(&header).await?;
    stream.shutdown().await
}

pub(super) async fn read_response(
    stream: &mut (impl AsyncRead + Unpin),
) -> io::Result<Result<ArmoredSignature, Failure>> {
    let mut header = [0_u8; RESPONSE_HEADER_LEN];
    stream.read_exact(&mut header).await?;
    if header[..4] != MAGIC || header[4] != VERSION {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "unsupported OpenPGP agent response",
        ));
    }
    if let Some(failure) = Failure::from_status(header[5]) {
        require_eof(stream, "OpenPGP agent failure response has trailing data").await?;
        return Ok(Err(failure));
    }
    if header[5] != SUCCESS {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "unknown OpenPGP agent response status",
        ));
    }
    let created = u32::from_be_bytes([header[6], header[7], header[8], header[9]]);
    let signature_len =
        u32::from_be_bytes([header[10], header[11], header[12], header[13]]) as usize;
    if signature_len > MAX_SIGNATURE_LEN {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "OpenPGP agent signature exceeds its size limit",
        ));
    }
    let mut fingerprint = [0_u8; FINGERPRINT_LEN];
    stream.read_exact(&mut fingerprint).await?;
    let fingerprint = from_utf8(&fingerprint)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?
        .parse::<Fingerprint>()
        .map_err(|_error| {
            io::Error::new(
                ErrorKind::InvalidData,
                "invalid OpenPGP agent signature response",
            )
        })?;
    let mut armored = vec![0_u8; signature_len];
    stream.read_exact(&mut armored).await?;
    let armored = String::from_utf8(armored)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
    let armored = ArmoredSignature::parse(armored).map_err(|_error| {
        io::Error::new(
            ErrorKind::InvalidData,
            "invalid OpenPGP agent signature response",
        )
    })?;
    if armored.created() != created || armored.fingerprint() != &fingerprint {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "OpenPGP agent signature metadata does not match its response frame",
        ));
    }
    require_eof(stream, "OpenPGP agent response has trailing data").await?;
    Ok(Ok(armored))
}

async fn require_eof(
    stream: &mut (impl AsyncRead + Unpin),
    message: &'static str,
) -> io::Result<()> {
    let mut trailing = [0_u8; 1];
    if stream.read(&mut trailing).await? == 0 {
        Ok(())
    } else {
        Err(io::Error::new(ErrorKind::InvalidData, message))
    }
}

fn frame_prefix(code: u8) -> [u8; 6] {
    [MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], VERSION, code]
}

fn checked_frame_len<T>(len: usize, max: usize, message: &'static str) -> io::Result<T>
where
    T: TryFrom<usize>,
{
    if len > max {
        return Err(io::Error::new(ErrorKind::InvalidInput, message));
    }
    T::try_from(len).map_err(|_error| io::Error::new(ErrorKind::InvalidInput, message))
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    const CREATED: u32 = 1_700_000_001;
    const FINGERPRINT: &str = "13FFC7DF20CD6ABFCAED58992D007ACDCD30CCA6";
    const ARMORED_SIGNATURE: &str = r#"-----BEGIN PGP SIGNATURE-----

wjcEABMIAB0FgmVT8QEWIQQT/8ffIM1qv8rtWJktAHrNzTDMpgAKCRAtAHrNzTDMphISAAEBAAIC
=0Ren
-----END PGP SIGNATURE-----
"#;

    fn armored_signature() -> String {
        ARMORED_SIGNATURE.to_owned()
    }

    fn request_frame(key: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(b"TKGP\x01\x01");
        frame.extend_from_slice(&(key.len() as u16).to_be_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(key);
        frame.extend_from_slice(payload);
        frame
    }

    fn response_frame(fingerprint: &[u8], created: u32, armored: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(b"TKGP\x01\x00");
        frame.extend_from_slice(&created.to_be_bytes());
        frame.extend_from_slice(&(armored.len() as u32).to_be_bytes());
        frame.extend_from_slice(fingerprint);
        frame.extend_from_slice(armored);
        frame
    }

    fn io_error<T>(result: io::Result<T>) -> io::Error {
        match result {
            Ok(_) => panic!("expected an I/O error"),
            Err(error) => error,
        }
    }

    fn successful_signature(
        result: io::Result<Result<ArmoredSignature, Failure>>,
    ) -> ArmoredSignature {
        match result {
            Ok(Ok(signature)) => signature,
            Ok(Err(_)) => panic!("expected a signature response"),
            Err(error) => panic!("expected a valid response: {error}"),
        }
    }

    #[tokio::test]
    async fn writes_exact_request_frame() {
        let key = "0123456789ABCDEF".parse().unwrap();
        let mut output = Vec::new();

        write_request(&mut output, Some(&key), b"payload")
            .await
            .unwrap();

        assert_eq!(
            output,
            b"TKGP\x01\x01\x00\x10\x00\x00\x00\x070123456789ABCDEFpayload"
        );
    }

    #[tokio::test]
    async fn rejects_oversized_payload_without_writing() {
        let oversized_payload = vec![0_u8; MAX_PAYLOAD_LEN + 1];
        let mut output = Vec::new();
        let error = write_request(&mut output, None, &oversized_payload)
            .await
            .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "payload is too large");
        assert!(output.is_empty());
    }

    #[tokio::test]
    async fn writes_request_at_size_limits() {
        let key = "A".repeat(MAX_KEY_LEN).parse().unwrap();
        let payload = vec![0_u8; MAX_PAYLOAD_LEN];
        let mut output = Vec::new();

        write_request(&mut output, Some(&key), &payload)
            .await
            .unwrap();

        assert_eq!(output, request_frame(key.as_str().as_bytes(), &payload));
    }

    #[tokio::test]
    async fn reads_fragmented_request_and_roundtrips_empty_key() {
        let expected = request_frame(&[], b"fragmented payload");
        let (mut writer, mut reader) = duplex(1);
        let write = tokio::spawn(async move {
            for byte in expected {
                writer.write_all(&[byte]).await.unwrap();
            }
            writer.shutdown().await.unwrap();
        });

        let request = read_request(&mut reader).await.unwrap();
        write.await.unwrap();

        assert_eq!(request.key, None);
        assert_eq!(request.payload, b"fragmented payload");
    }

    #[tokio::test]
    async fn rejects_malformed_truncated_and_trailing_requests() {
        let mut cases = vec![
            (
                b"BAD!\x01\x01\x00\x00\x00\x00\x00\x00".to_vec(),
                ErrorKind::InvalidData,
            ),
            (
                b"TKGP\x02\x01\x00\x00\x00\x00\x00\x00".to_vec(),
                ErrorKind::InvalidData,
            ),
            (
                b"TKGP\x01\x02\x00\x00\x00\x00\x00\x00".to_vec(),
                ErrorKind::InvalidData,
            ),
            (
                request_frame(b"0123456789ABCDEF", b"payload")[..20].to_vec(),
                ErrorKind::UnexpectedEof,
            ),
        ];
        let mut trailing = request_frame(b"0123456789ABCDEF", b"payload");
        trailing.push(0);
        cases.push((trailing, ErrorKind::InvalidData));

        for (frame, expected_kind) in cases {
            let error = io_error(read_request(&mut frame.as_slice()).await);
            assert_eq!(error.kind(), expected_kind);
        }
    }

    #[tokio::test]
    async fn rejects_malformed_key_identifiers() {
        for key in [b"short".as_slice(), b"0123456789ABCDEG", &[0xff]] {
            let error = io_error(read_request(&mut request_frame(key, b"").as_slice()).await);
            assert_eq!(error.kind(), ErrorKind::InvalidData);
        }
    }

    #[tokio::test]
    async fn rejects_oversized_request_lengths_before_reading_bodies() {
        let mut oversized_key = request_frame(&[], b"");
        oversized_key[6..8].copy_from_slice(&((MAX_KEY_LEN + 1) as u16).to_be_bytes());
        let mut oversized_payload = request_frame(&[], b"");
        oversized_payload[8..12].copy_from_slice(&((MAX_PAYLOAD_LEN + 1) as u32).to_be_bytes());

        for frame in [oversized_key, oversized_payload] {
            let error = io_error(read_request(&mut frame.as_slice()).await);
            assert_eq!(error.kind(), ErrorKind::InvalidData);
            assert_eq!(
                error.to_string(),
                "OpenPGP agent request exceeds its size limit"
            );
        }
    }

    #[tokio::test]
    async fn writes_exact_signature_frame_and_reads_it_back() {
        let armored = armored_signature();
        let expected = response_frame(FINGERPRINT.as_bytes(), CREATED, armored.as_bytes());
        let signature = ArmoredSignature::parse(armored).unwrap();
        let mut output = Vec::new();

        write_signature(&mut output, &signature).await.unwrap();

        assert_eq!(output, expected);
        let decoded = successful_signature(read_response(&mut output.as_slice()).await);
        assert!(decoded == signature);
    }

    #[tokio::test]
    async fn rejects_oversized_signature_lengths() {
        let error = checked_frame_len::<u32>(
            MAX_SIGNATURE_LEN + 1,
            MAX_SIGNATURE_LEN,
            "signature is too large",
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "signature is too large");
    }

    #[tokio::test]
    async fn failure_frames_are_exact_and_decode_to_typed_failures() {
        let cases = [
            (Failure::InvalidRequest, Failure::InvalidRequest as u8),
            (Failure::KeyNotServed, Failure::KeyNotServed as u8),
            (Failure::SigningFailed, Failure::SigningFailed as u8),
        ];

        for (failure, status) in cases {
            let mut output = Vec::new();
            write_failure(&mut output, failure).await.unwrap();
            let mut expected = [0_u8; RESPONSE_HEADER_LEN];
            expected[..4].copy_from_slice(&MAGIC);
            expected[4] = VERSION;
            expected[5] = status;
            assert_eq!(output, expected);

            let decoded = read_response(&mut output.as_slice()).await.unwrap();
            assert!(matches!(decoded, Err(failure) if failure as u8 == status));
        }

        let mut trailing = [0_u8; RESPONSE_HEADER_LEN + 1];
        trailing[..4].copy_from_slice(&MAGIC);
        trailing[4] = VERSION;
        trailing[5] = Failure::SigningFailed as u8;
        let error = io_error(read_response(&mut trailing.as_slice()).await);
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn rejects_malformed_truncated_trailing_and_oversized_responses() {
        let armored = armored_signature();
        let valid = response_frame(FINGERPRINT.as_bytes(), CREATED, armored.as_bytes());
        let mut cases = Vec::new();
        let mut bad_magic = valid.clone();
        bad_magic[0] = b'X';
        cases.push((bad_magic, ErrorKind::InvalidData));
        let mut bad_status = valid.clone();
        bad_status[5] = 99;
        cases.push((bad_status, ErrorKind::InvalidData));
        cases.push((valid[..valid.len() - 1].to_vec(), ErrorKind::UnexpectedEof));
        let mut trailing = valid.clone();
        trailing.push(0);
        cases.push((trailing, ErrorKind::InvalidData));
        let mut oversized = valid;
        oversized[10..14].copy_from_slice(&((MAX_SIGNATURE_LEN + 1) as u32).to_be_bytes());
        oversized.truncate(RESPONSE_HEADER_LEN);
        cases.push((oversized, ErrorKind::InvalidData));

        for (frame, expected_kind) in cases {
            let error = io_error(read_response(&mut frame.as_slice()).await);
            assert_eq!(error.kind(), expected_kind);
        }
    }

    #[tokio::test]
    async fn validates_fingerprint_and_complete_armor_when_reading() {
        let armored = armored_signature();
        let invalid_armor = [
            "not armored".to_owned(),
            armored.replacen("wj", "not-base64", 1),
            armored.replace("=0Ren", "=AAAA"),
            armored.replace(
                r#"=0Ren
"#,
                "",
            ),
        ];
        let mut invalid_frames = vec![response_frame(
            b"Z123456789ABCDEF0123456789ABCDEF01234567",
            0,
            armored.as_bytes(),
        )];
        invalid_frames.extend(
            invalid_armor
                .into_iter()
                .map(|armored| response_frame(FINGERPRINT.as_bytes(), CREATED, armored.as_bytes())),
        );
        for frame in invalid_frames {
            let error = io_error(read_response(&mut frame.as_slice()).await);
            assert_eq!(error.kind(), ErrorKind::InvalidData);
            assert_eq!(
                error.to_string(),
                "invalid OpenPGP agent signature response"
            );
        }
    }

    #[tokio::test]
    async fn rejects_frame_metadata_that_disagrees_with_the_signature_packet() {
        let armored = armored_signature();
        let other_fingerprint = b"23FFC7DF20CD6ABFCAED58992D007ACDCD30CCA6";
        for frame in [
            response_frame(FINGERPRINT.as_bytes(), CREATED - 1, armored.as_bytes()),
            response_frame(other_fingerprint, CREATED, armored.as_bytes()),
        ] {
            let error = io_error(read_response(&mut frame.as_slice()).await);
            assert_eq!(error.kind(), ErrorKind::InvalidData);
            assert_eq!(
                error.to_string(),
                "OpenPGP agent signature metadata does not match its response frame"
            );
        }
    }

    #[tokio::test]
    async fn reads_fragmented_signature_response_over_duplex_stream() {
        let armored = armored_signature();
        let expected = response_frame(FINGERPRINT.as_bytes(), CREATED, armored.as_bytes());
        let (mut writer, mut reader) = duplex(2);
        let write = tokio::spawn(async move {
            for chunk in expected.chunks(2) {
                writer.write_all(chunk).await.unwrap();
            }
            writer.shutdown().await.unwrap();
        });

        let signature = successful_signature(read_response(&mut reader).await);
        write.await.unwrap();

        assert!(signature == ArmoredSignature::parse(armored).unwrap());
    }
}
