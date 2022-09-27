use chacha20poly1305::{
    aead::{Aead, NewAead},
    ChaCha20Poly1305, Key, Nonce,
};

/// Chacha20-Poly1305 encryption
///
/// # Arguments
///
/// * `msg` - text to be encrypted
/// * `key` - encryption key
pub fn chacha20poly1305_encrypt(key: &[u8; 32], msg: &[u8]) -> Vec<u8> {
    let key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce = Nonce::default();

    let output = cipher
        .encrypt(&nonce, msg.as_ref())
        .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

    output
}

/// Chacha20-Poly1305 decryption
///
/// # Arguments
///
/// * `encrypted_msg` - text to be decrypted
/// * `key` - decryption key
///
pub fn chacha20poly1305_decrypt(key: &[u8; 32], encrypted_msg: &[u8]) -> Vec<u8> {
    let key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce = Nonce::default();

    let output = cipher
        .decrypt(&nonce, encrypted_msg.as_ref())
        .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

    output
}
