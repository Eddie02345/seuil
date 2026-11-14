//! Cryptography for the Samsung account sign-in envelope and certificate request.
//!
//! Samsung's SDK sign-in binds the browser login to the client with an envelope:
//! PBKDF2-HMAC-SHA256 derives an AES-128 key from a random salt, the JSON
//! parameters are encrypted with AES-128-CBC, and the AES key is wrapped with
//! the account SDK's RSA public key (PKCS#1 v1.5). The callback repeats the
//! AES step with keys carried inside the callback itself.

use aes::Aes128;
use aes::cipher::{BlockDecrypt, KeyInit};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use rand::RngCore;
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{AuthError, Result};

type CbcEncryptor = cbc::Encryptor<Aes128>;

const ENVELOPE_ITERATION_LIMIT: u32 = 1_000_000;

pub fn random_bytes(count: usize) -> Vec<u8> {
    let mut data = vec![0u8; count];
    rand::thread_rng().fill_bytes(&mut data);
    data
}

pub fn base64_standard(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn base64_url_no_pad(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Builds the base64 `svcParam` value from the login payload.
pub fn build_envelope(payload: &Value, iterations: u32, pki_public_key: &str) -> Result<String> {
    if !(1..=ENVELOPE_ITERATION_LIMIT).contains(&iterations) {
        return Err(AuthError::Protocol(format!(
            "Samsung sign-in iteration count {iterations} is out of range"
        )));
    }
    let der = STANDARD
        .decode(pki_public_key)
        .map_err(|e| AuthError::Crypto(format!("invalid Samsung public key encoding: {e}")))?;
    let rsa = parse_public_key(&der)?;

    // Samsung derives the PBKDF2 password from the decimal iteration count.
    let password = base64_standard(&sha256(iterations.to_string().as_bytes()));
    let salt = random_bytes(16);
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iterations, &mut key);

    let encrypted_key = rsa
        .encrypt(
            &mut rand::thread_rng(),
            Pkcs1v15Encrypt,
            base64_standard(&key).as_bytes(),
        )
        .map_err(|e| AuthError::Crypto(format!("could not wrap the sign-in key: {e}")))?;

    let iv = random_bytes(16);
    let mut iv_array = [0u8; 16];
    iv_array.copy_from_slice(&iv);
    let plaintext = serde_json::to_vec(payload)?;
    let ciphertext = aes128_cbc_encrypt(&key, &iv_array, &plaintext)?;

    let envelope = json!({
        "chkDoNum": iterations.to_string(),
        "svcEncParam": base64_standard(&ciphertext),
        "svcEncKY": base64_standard(&encrypted_key),
        "svcEncIV": hex::encode(iv),
    });
    Ok(base64_standard(&serde_json::to_vec(&envelope)?))
}

/// Decrypts a hex-encoded AES-128-ECB callback field. Samsung pads short keys
/// with zero bytes and always uses PKCS#7 padding.
pub fn callback_decrypt(value: &str, key: &str) -> Result<String> {
    if value.is_empty() || value.len() > 32_768 || !value.len().is_multiple_of(2) {
        return Err(AuthError::Protocol(
            "Samsung sign-in callback field has an invalid length".into(),
        ));
    }
    let ciphertext = hex::decode(value)
        .map_err(|e| AuthError::Protocol(format!("invalid sign-in callback encoding: {e}")))?;
    if ciphertext.len() % 16 != 0 {
        return Err(AuthError::Protocol(
            "Samsung sign-in callback field is not a whole AES block".into(),
        ));
    }

    let mut secret = [0u8; 16];
    for (slot, byte) in secret.iter_mut().zip(key.as_bytes()) {
        *slot = *byte;
    }
    let cipher = Aes128::new_from_slice(&secret)
        .map_err(|e| AuthError::Crypto(format!("invalid sign-in callback key: {e}")))?;
    let mut plaintext = ciphertext;
    for block in plaintext.as_chunks_mut::<16>().0 {
        cipher.decrypt_block(block.into());
    }
    let pad = *plaintext
        .last()
        .ok_or_else(|| AuthError::Protocol("empty sign-in callback field".into()))?
        as usize;
    if pad == 0 || pad > 16 || pad > plaintext.len() {
        return Err(AuthError::Protocol(
            "Samsung sign-in callback padding is invalid".into(),
        ));
    }
    plaintext.truncate(plaintext.len() - pad);
    String::from_utf8(plaintext)
        .map_err(|e| AuthError::Protocol(format!("sign-in callback is not UTF-8: {e}")))
}

pub fn pbkdf2_sha1_16(password: &[u8], salt: &[u8]) -> [u8; 16] {
    let mut output = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, salt, 30, &mut output);
    output
}

/// Generates a PKCS#10 certificate request with Samsung's subject layout and
/// returns the base64 CSR together with the base64 PKCS#1 private key.
pub fn make_csr(device_id: &str) -> Result<(String, String)> {
    if device_id.is_empty() || device_id.len() >= 256 {
        return Err(AuthError::Protocol(
            "invalid Continuity registration identifier".into(),
        ));
    }
    let mut rng = rand::thread_rng();
    let private = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| AuthError::Crypto(format!("could not create certificate key: {e}")))?;
    let public_der = private
        .to_public_key()
        .to_pkcs1_der()
        .map_err(|e| AuthError::Crypto(format!("could not encode certificate key: {e}")))?
        .as_bytes()
        .to_vec();
    let private_der = private
        .to_pkcs1_der()
        .map_err(|e| AuthError::Crypto(format!("could not encode certificate key: {e}")))?
        .as_bytes()
        .to_vec();

    let rsa_algorithm = der_sequence(
        &[
            der(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1]),
            der(0x05, &[]),
        ]
        .concat(),
    );
    let signing_algorithm = der_sequence(
        &[
            der(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 11]),
            der(0x05, &[]),
        ]
        .concat(),
    );

    let name = der_sequence(
        &[
            attribute(&[0x55, 4, 3], device_id, 0x0c),
            attribute(&[0x55, 4, 10], "Samsung Electronics", 0x0c),
            attribute(&[0x55, 4, 11], "CSP", 0x0c),
            attribute(&[0x55, 4, 7], "", 0x0c),
            attribute(&[0x55, 4, 8], "", 0x0c),
            attribute(&[0x55, 4, 6], "KR", 0x13),
            attribute(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 1], "", 0x16),
        ]
        .concat(),
    );
    let subject_public_key =
        der_sequence(&[rsa_algorithm, der(0x03, &bit_string(&public_der))].concat());
    let info = der_sequence(&[der(0x02, &[0]), name, subject_public_key, der(0xa0, &[])].concat());

    let signing_key = SigningKey::<Sha256>::new(private);
    let signature = signing_key.sign(&info).to_vec();
    let csr = der_sequence(&[info, signing_algorithm, der(0x03, &bit_string(&signature))].concat());

    Ok((base64_standard(&csr), base64_standard(&private_der)))
}

fn aes128_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>> {
    let encryptor = CbcEncryptor::new_from_slices(key, iv)
        .map_err(|e| AuthError::Crypto(format!("invalid AES-CBC parameters: {e}")))?;
    Ok(encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}

fn parse_public_key(der: &[u8]) -> Result<RsaPublicKey> {
    RsaPublicKey::from_public_key_der(der)
        .or_else(|_| RsaPublicKey::from_pkcs1_der(der))
        .map_err(|e| AuthError::Crypto(format!("unsupported Samsung public key: {e}")))
}

fn attribute(oid: &[u8], text: &str, tag: u8) -> Vec<u8> {
    der(
        0x31,
        &der_sequence(&[der(0x06, oid), der(tag, text.as_bytes())].concat()),
    )
}

/// Wraps DER content in a tag/length header.
fn der(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    output.extend(der_length(value.len()));
    output.extend_from_slice(value);
    output
}

fn der_sequence(value: &[u8]) -> Vec<u8> {
    der(0x30, value)
}

fn der_length(length: usize) -> Vec<u8> {
    if length < 128 {
        return vec![length as u8];
    }
    let mut bytes = Vec::new();
    let mut remaining = length;
    while remaining > 0 {
        bytes.insert(0, (remaining & 0xff) as u8);
        remaining >>= 8;
    }
    let mut output = vec![0x80 | bytes.len() as u8];
    output.extend(bytes);
    output
}

fn bit_string(value: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(value.len() + 1);
    output.push(0);
    output.extend_from_slice(value);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_length_encodes_short_and_long_forms() {
        assert_eq!(der_length(5), vec![5]);
        assert_eq!(der_length(200), vec![0x81, 200]);
        assert_eq!(der_length(300), vec![0x82, 1, 44]);
    }

    #[test]
    fn callback_round_trip_with_zero_padded_key() {
        let key = "0123456789abcdefEXTRA";
        let plaintext = b"https://eu-auth2.samsungosp.com";
        let mut padded = plaintext.to_vec();
        let pad = 16 - (padded.len() % 16);
        padded.extend(std::iter::repeat_n(pad as u8, pad));

        let cipher = Aes128::new_from_slice(&key.as_bytes()[..16]).expect("valid key");
        use aes::cipher::BlockEncrypt;
        for block in padded.as_chunks_mut::<16>().0 {
            cipher.encrypt_block(block.into());
        }
        let encoded = hex::encode(&padded);
        let decoded = callback_decrypt(&encoded, key).expect("callback decrypts");
        assert_eq!(decoded, "https://eu-auth2.samsungosp.com");
    }

    #[test]
    fn identity_identifiers_are_stable() {
        let first = pbkdf2_sha1_16(b"deviceIDboz0m1awhe", b"smcfcore");
        let second = pbkdf2_sha1_16(b"deviceIDboz0m1awhe", b"smcfcore");
        assert_eq!(first, second);
    }

    #[test]
    fn envelope_round_trips_with_a_generated_key() {
        use cbc::cipher::BlockDecryptMut;
        use rsa::pkcs8::EncodePublicKey;

        let private = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("generate test key");
        let public = STANDARD.encode(
            private
                .to_public_key()
                .to_public_key_der()
                .expect("encode test key")
                .as_bytes(),
        );
        let payload = json!({ "clientId": "test-client", "state": "abc123" });

        let envelope_b64 = build_envelope(&payload, 1000, &public).expect("build envelope");
        let envelope: Value =
            serde_json::from_slice(&STANDARD.decode(envelope_b64).unwrap()).unwrap();
        assert_eq!(envelope["chkDoNum"], "1000");

        let wrapped = STANDARD
            .decode(envelope["svcEncKY"].as_str().unwrap())
            .unwrap();
        let key_b64 = private.decrypt(Pkcs1v15Encrypt, &wrapped).unwrap();
        let key: [u8; 16] = STANDARD
            .decode(String::from_utf8(key_b64).unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let iv: [u8; 16] = hex::decode(envelope["svcEncIV"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let ciphertext = STANDARD
            .decode(envelope["svcEncParam"].as_str().unwrap())
            .unwrap();
        let plaintext = cbc::Decryptor::<Aes128>::new_from_slices(&key, &iv)
            .unwrap()
            .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
            .unwrap();
        let decoded: Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(decoded, payload);
    }
}
