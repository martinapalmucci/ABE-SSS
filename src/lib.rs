pub mod sss;

use core::num;
use std::io::{Error, ErrorKind};

use thiserror::Error;

use chacha20poly1305::{
    aead::{Aead, NewAead},
    ChaCha20Poly1305, Key, Nonce,
};
use curve25519_dalek_ng::{
    constants,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand_core::OsRng;

/// Returns a keypair. The first element is private key and the second one is public key.
///
/// # Arguments
///
/// * `csprng` - cryptographically secure pseudorandom number generator
///
/// # Example
///
/// ```
/// let mut csprng = OsRng;
/// let keypair = generate_keypair(&mut csprng);
/// let (private_key, public_key) = keypair;
///
/// let g = constants::RISTRETTO_BASEPOINT_TABLE;
/// assert_eq!(&private_key * &g, public_key)
/// ```
#[must_use]
pub fn generate_keypair(csprng: &mut OsRng) -> (Scalar, RistrettoPoint) {
    let private_key = Scalar::random(csprng);
    let public_key = generate_public_key(&private_key);
    (private_key, public_key)
}

pub fn generate_public_key(private_key: &Scalar) -> RistrettoPoint {
    let generator = constants::RISTRETTO_BASEPOINT_TABLE;
    let public_key = private_key * &generator;
    public_key
}

/// Returns the symmetric cipher key for ECIES.
///
/// # Arguments
///
/// * `pkc` - sender's private key
/// * `pbk` - receiver's public key
///
fn key_derivation_fn(private_key: &Scalar, public_key: &RistrettoPoint) -> [u8; 32] {
    (private_key * public_key).compress().to_bytes()
}

/// Generates randomly an ephemeral private key, and its associated public key.
///
/// Derives the encryption key and encrypts the plaintext taken as input.
///
/// Writes a single message containing both the ciphertext and the public ephemeral value.
///
/// # Arguments
///
/// * `csprng` - cryptographically secure pseudorandom number generator
/// * `plaintext` - text to be encrypted
/// * `pbk` - receiver's public key
///
#[must_use]
pub fn process_encryption(
    plaintext: &[u8],
    public_key: &RistrettoPoint,
) -> (Vec<u8>, RistrettoPoint) {
    let mut csprng = OsRng;
    let (ephemeral_pkc, ephemeral_pbk) = generate_keypair(&mut csprng);
    let ciphertext = encrypt(plaintext, &key_derivation_fn(&ephemeral_pkc, &public_key));
    (ciphertext, ephemeral_pbk)
}

/// Returns the ciphertext.
///
/// # Arguments
///
/// * `plaintext` - text to be encrypted
/// * `cipher_key` - encryption key
///
fn encrypt(plaintext: &[u8], cipher_key: &[u8; 32]) -> Vec<u8> {
    let key = Key::from_slice(cipher_key);
    let cipher = ChaCha20Poly1305::new(key);

    let ciphertext = cipher
        .encrypt(&Nonce::default(), plaintext.as_ref())
        .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

    ciphertext
}

/// Reads the message to get ciphertext and sender's public key.
///
/// Derives the decryption key and decrypts the ciphertext taken as input.
///
/// Returns the plaintext.
///
/// # Arguments
///
/// * `message` - received message
///
#[must_use]
pub fn process_decryption(
    ciphertext: &[u8],
    public_key: &RistrettoPoint,
    private_key: &Scalar,
) -> Vec<u8> {
    decrypt(ciphertext, &key_derivation_fn(&private_key, &public_key))
}

/// Returns the plaintext.
///
/// # Arguments
///
/// * `ciphertext` - text to be decrypted
/// * `cipher_key` - decryption key
///
fn decrypt(ciphertext: &[u8], cipher_key: &[u8; 32]) -> Vec<u8> {
    let key = Key::from_slice(cipher_key);
    let cipher = ChaCha20Poly1305::new(key);

    let plaintext = cipher
        .decrypt(&Nonce::default(), ciphertext.as_ref())
        .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

    plaintext
}

/// Returns the concatenation of ciphertext and sender's public key.
///
/// # Arguments
///
/// * `ciphertext` - encrypted text
/// * `pbk` - sender's public key
///
pub fn write_message(ciphertext: &Vec<u8>, public_key: &RistrettoPoint) -> Vec<u8> {
    let mut message: Vec<u8> = Vec::new();
    message.extend_from_slice(ciphertext);
    message.extend_from_slice(&public_key.compress().to_bytes());
    message
}

/// Returns the ciphertext and the sender's public key contained in message.
///
/// # Arguments
///
/// * `message` - message to be read
///
pub fn read_message(message: &[u8]) -> (&[u8], Option<RistrettoPoint>) {
    let (ciphertext, pbk) = message.split_at(message.len() - 32);
    let pbk = CompressedRistretto::from_slice(pbk).decompress();
    (ciphertext, pbk)
}

pub fn chain_point(point: &(Scalar, Scalar)) -> Vec<u8> {
    let fst = point.0.to_bytes();
    let snd = point.1.to_bytes();
    concat_arrays(fst, snd)
}

fn concat_arrays<const N: usize, const M: usize>(fst: [u8; N], snd: [u8; M]) -> Vec<u8> {
    let mut result = Vec::new();
    for n in 0..(N + M) {
        let cond = n < N;
        let i = if cond { n } else { n - N };
        let value = (cond as u8) * fst[i] + (!cond as u8) * snd[i];
        result.push(value)
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek_ng::scalar::Scalar;
    use rand_core::OsRng;

    #[test]
    fn encryption_decryption_test() {
        let mut csprng = OsRng;

        let original_text = b"plaintext message";
        let attribute_keypair = generate_keypair(&mut csprng);

        // Encryption process

        let attribute_pbk = attribute_keypair.1;
        let (ciphertext, ephemeral_pbk) = process_encryption(original_text, &attribute_pbk);

        // Decryption process

        let attribute_pkc = attribute_keypair.0;
        let plaintext = process_decryption(&ciphertext, &ephemeral_pbk, &attribute_pkc);

        assert_eq!(plaintext, original_text.to_vec());
    }
}
