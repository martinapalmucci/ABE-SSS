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

#[derive(Error, Debug)]
pub enum SSSError {
    #[error("threshold out of range")]
    ThresholdOutRange,
}

fn check_threshold(threshold: usize, number_shares: usize) -> bool {
    (1 <= threshold) & (threshold <= number_shares)
}

/// Returns the shares of Shamir's Secret Sharing algorithm.
///
/// # Arguments
///
/// * `secret` - constant term of the polynomial
/// * `threshold` - degree of the polynomial
/// * `number_shares` - number of shares (or points) to be generated
///
#[must_use]
pub fn make_random_shares(
    secret: Scalar,
    threshold: usize,
    number_shares: usize,
) -> Result<Vec<(Scalar, Scalar)>, SSSError> {
    match check_threshold(threshold, number_shares) {
        true => {
            let mut csprng = OsRng;
            let mut polynomial = vec![secret];
            polynomial.extend(gen_random_vec(&mut csprng, threshold - 1));
            let shares = compute_random_points(&mut csprng, &polynomial, number_shares);
            Ok(shares)
        }
        _ => Err(SSSError::ThresholdOutRange),
    }
}

/// Returns a scalar random vector.
///
/// # Arguments
///
/// * `csprng` - cryptographically secure pseudorandom number generator
/// * `length` - number of elements in resulting vector
///
fn gen_random_vec(csprng: &mut OsRng, length: usize) -> Vec<Scalar> {
    (0..length).map(|_| Scalar::random(csprng)).collect()
}

/// Returns a vector of (x, y) points based of a polynomial.
///
/// # Arguments
///
/// * `csprng` - cryptographically secure pseudorandom number generato
/// * `polynomial` - coefficients a_0, ..., a_n of the polynomial
/// * `n_points` - number of points to be computed
///
fn compute_random_points(
    csprng: &mut OsRng,
    polynomial: &[Scalar],
    n_points: usize,
) -> Vec<(Scalar, Scalar)> {
    let mut points = Vec::<(Scalar, Scalar)>::new();
    for _ in 0..n_points {
        let x = Scalar::random(csprng);
        let y = evaluate_polynomial(polynomial, x);
        points.push((x, y));
    }
    points
}

/// Returns the evaluation of a polynomial in the x-coordinate.
///
/// # Arguments
///
/// * `polynomial` - coefficients a_0, ..., a_n of the polynomial
/// * `x` - input coordinate
///
fn evaluate_polynomial(polynomial: &[Scalar], x: Scalar) -> Scalar {
    let mut y: Scalar = Scalar::zero();

    let mut curr_exp = Scalar::one();
    for a_i in polynomial {
        y += a_i * curr_exp;
        curr_exp *= x;
    }
    y
}

/// Returns the recovered secret.
#[must_use]
pub fn recover_secret(shares: &[(Scalar, Scalar)], threshold: usize) -> Result<Scalar, SSSError> {
    match check_threshold(threshold, shares.len()) {
        true => Ok(lagrange_interpolate(Scalar::zero(), shares)),
        _ => Err(SSSError::ThresholdOutRange),
    }
}

/// Returns the result of the Lagrange interpolation.
fn lagrange_interpolate(x: Scalar, points: &[(Scalar, Scalar)]) -> Scalar {
    let mut y: Scalar = Scalar::default();

    for (j, (_, y_j)) in points.iter().enumerate() {
        let l_j = lagrange_polynomial(j, points, x);
        y += y_j * l_j;
    }

    y
}

/// Returns the result of the Lagrange polynomial
fn lagrange_polynomial(j: usize, points: &[(Scalar, Scalar)], x: Scalar) -> Scalar {
    let mut l_j: Scalar = Scalar::one();

    let x_j = points[j].0;

    for (m, (x_m, _)) in points.iter().enumerate() {
        if m != j {
            l_j *= (x - x_m) * (x_j - x_m).invert();
        }
    }
    l_j
}

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
    fn lagrange_interpolation_test() {
        let mut csprng = OsRng;

        let rnd = Scalar::random(&mut csprng);

        let point0: (Scalar, Scalar) = (Scalar::zero(), Scalar::zero());
        let point1: (Scalar, Scalar) = (Scalar::one(), rnd);
        let two = Scalar::one() + Scalar::one();
        let point2: (Scalar, Scalar) = (two, two * rnd);

        let mut points = Vec::<(Scalar, Scalar)>::new();
        points.push(point0);
        points.push(point1);
        points.push(point2);

        let ret = lagrange_interpolate(Scalar::one(), &points);

        assert_eq!(ret, rnd);
    }

    #[test]
    fn sss_test() {
        let threshold = 3;
        let n_shares = 6; // try with multiple sets

        let mut csprng = OsRng;
        let secret = Scalar::random(&mut csprng);

        let shares = make_random_shares(secret, threshold, n_shares).unwrap();
        let recov_secret = recover_secret(&shares, threshold).unwrap();

        assert_eq!(secret, recov_secret);
    }

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
