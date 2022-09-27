use curve25519_dalek_ng::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};

use crate::{
    chachapoly::{chacha20poly1305_decrypt, chacha20poly1305_encrypt},
    utils::{generate_keypair, key_derivation_fn},
};

/// Encrypt a message by a public key
///
/// # Arguments
///
/// * `msg` - The u8 array reference of the message to encrypt
/// * `receiver_pub` - The RistrettoPoint reference of a receiver's public key
#[must_use]
pub fn ecies_encrypt(msg: &[u8], receiver_pub: &RistrettoPoint) -> Vec<u8> {
    let (ephemeral_sk, ephemeral_pk) = generate_keypair();

    let chacha_key = key_derivation_fn(&ephemeral_sk, &receiver_pub);
    let encrypted_msg = chacha20poly1305_encrypt(&chacha_key, msg);

    let mut ciphertext: Vec<u8> = Vec::new();
    ciphertext.extend_from_slice(&encrypted_msg);
    ciphertext.extend_from_slice(&ephemeral_pk.compress().to_bytes());

    ciphertext
}

/// Decrypt a message by a secret key
///
/// # Arguments
///
/// * `msg` - The u8 array reference of the encrypted message
/// * `receiver_sec` - The Scalar reference of a receiver's secret key
#[must_use]
pub fn ecies_decrypt(msg: &[u8], receiver_sec: &Scalar) -> Vec<u8> {
    let (encrypted, ephemeral_pk) = msg.split_at(msg.len() - 32);
    let ephemeral_pk = CompressedRistretto::from_slice(ephemeral_pk)
        .decompress()
        .unwrap();

    let chacha_key = key_derivation_fn(&receiver_sec, &ephemeral_pk);
    chacha20poly1305_decrypt(&chacha_key, encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_decryption_test() {
        let original_text = b"plaintext message";
        let attribute_keypair = generate_keypair();

        // Encryption process

        let attribute_pbk = attribute_keypair.1;
        let msg = ecies_encrypt(original_text, &attribute_pbk);

        // Decryption process

        let attribute_pkc = attribute_keypair.0;
        let output = ecies_decrypt(&msg, &attribute_pkc);

        assert_eq!(output, original_text.to_vec());
    }
}
