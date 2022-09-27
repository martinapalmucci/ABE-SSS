use curve25519_dalek_ng::{constants, ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::OsRng;

/// Returns a keypair. The first element is private key and the second one is public key.
///
/// # Example
///
/// ```
/// let keypair = generate_keypair();
/// let (private_key, public_key) = keypair;
///
/// let g = constants::RISTRETTO_BASEPOINT_TABLE;
/// assert_eq!(&private_key * &g, public_key)
/// ```
#[must_use]
pub fn generate_keypair() -> (Scalar, RistrettoPoint) {
    let private_key = Scalar::random(&mut OsRng);
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
pub fn key_derivation_fn(private_key: &Scalar, public_key: &RistrettoPoint) -> [u8; 32] {
    (private_key * public_key).compress().to_bytes()
}
