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

// SSS algorithm

// Making random shares
#[must_use]
pub fn make_random_shares(
    secret: Scalar,
    threshold: usize,
    n_shares: usize,
) -> Vec<(Scalar, Scalar)> {
    /* makes random shares
     */

    // check if threshold < n_shares

    let mut p = vec![secret];
    p.extend(generate_random_vector(threshold - 1));

    let x_coordinate = generate_random_vector(n_shares);
    get_shares(&x_coordinate, &p)
}

fn generate_random_vector(length: usize) -> Vec<Scalar> {
    /*  generates a random vector with
        "length" number of elements
    */
    let mut csprng = OsRng;

    let mut vec: Vec<Scalar> = Vec::new();
    for _ in 0..length {
        let v_i = Scalar::random(&mut csprng);
        vec.push(v_i);
    }
    vec
}

fn get_shares(x_vec: &[Scalar], polynomial: &[Scalar]) -> Vec<(Scalar, Scalar)> {
    /* reshapes the format of coordinates into points
     */
    let mut shares = Vec::<(Scalar, Scalar)>::new();

    for x_i in x_vec {
        let y_i = evaluate_polynomial(polynomial, *x_i);
        let share: (Scalar, Scalar) = (*x_i, y_i);
        shares.push(share);
    }
    shares
}

fn evaluate_polynomial(polynomial: &[Scalar], x: Scalar) -> Scalar {
    /*  returns the y-coordinates evaluated on a
        polinomial "p" in the x-coordinates "x"
    */
    let mut y: Scalar = Scalar::zero();

    let mut curr_exp = Scalar::one();
    for a_i in polynomial {
        y += a_i * curr_exp;
        curr_exp *= x;
    }
    y
}

// Recovering secret
#[must_use]
pub fn recover_secret(shares: &[(Scalar, Scalar)], threshold: usize) -> Scalar {
    assert!(shares.len() >= threshold);

    lagrange_interpolate(Scalar::zero(), shares)
}

// Lagrange interpolation
fn lagrange_interpolate(x: Scalar, points: &[(Scalar, Scalar)]) -> Scalar {
    let mut y: Scalar = Scalar::zero();

    for (j, (_, y_j)) in points.iter().enumerate() {
        let l_j = lagrange_polynomial(j, points, x);
        y += y_j * l_j;
    }

    y
}

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
    let generator = constants::RISTRETTO_BASEPOINT_TABLE;
    let public_key = &private_key * &generator;
    (private_key, public_key)
}

/// Returns the symmetric cipher key for ECIES.
///
/// # Arguments
///
/// * `pkc` - sender's private key
/// * `pbk` - receiver's public key
///
/// # Example
///
/// ```
/// let mut csprng = OsRng;
/// let g = constants::RISTRETTO_BASEPOINT_TABLE;
/// let Alice_pkc = Scalar::random(&mut csprng);
/// let Alice_pbk = &Alice_pkc * &g;
/// let Bob_pkc = Scalar::random(&mut csprng);
/// let Bob_pbk = &Bob_pkc * &g;
///
/// let K_A = key_derivation_fn(&Alice_pkc, &Bob_pbk);
/// let K_B = key_derivation_fn(&Bob_pkc, &Alice_pbk);
/// assert_eq!(K_A, K_B)
/// ```
fn key_derivation_fn(pkc: &Scalar, pbk: &RistrettoPoint) -> [u8; 32] {
    (pkc * pbk).compress().to_bytes()
}

/// Generates randomly an ephemeral private key, and its associated public key.
///
/// Derives the encryption key and encrypts the plaintext taken as input.
///
/// Writes a single message containing both the ciphertext and the public ephemeral value.
///
/// # Arguments
///
/// * `plaintext` - text to be encrypted
/// * `pbk` - receiver's public key
///
#[must_use]
pub fn process_encryption(csprng: &mut OsRng, plaintext: &[u8], pbk: &RistrettoPoint) -> Vec<u8> {
    let ephemeral_keypair = generate_keypair(csprng);
    let (ephemeral_pkc, ephemeral_pbk) = ephemeral_keypair;

    let cipher_key = key_derivation_fn(&ephemeral_pkc, &pbk);
    let ciphertext = encrypt(plaintext, &cipher_key);

    write_message(&ciphertext, &ephemeral_pbk)
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

/// Returns the concatenation of ciphertext and sender's public key.
///
/// # Arguments
///
/// * `ciphertext` - encrypted text
/// * `pbk` - sender's public key
///
fn write_message(ciphertext: &Vec<u8>, pbk: &RistrettoPoint) -> Vec<u8> {
    let mut message: Vec<u8> = Vec::new();
    message.append(&mut write_ciphertext(ciphertext));
    message.append(&mut write_pbk(pbk));
    message
}

fn write_ciphertext(ciphertext: &Vec<u8>) -> Vec<u8> {
    ciphertext.clone()
}

fn write_pbk(pbk: &RistrettoPoint) -> Vec<u8> {
    pbk.compress().to_bytes().to_vec()
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
pub fn process_decryption(message: &Vec<u8>, pkc: &Scalar) -> Vec<u8> {
    let (ciphertext, ephemeral_pbk) = read_message(&message);
    let cipher_key = key_derivation_fn(&pkc, &ephemeral_pbk);
    decrypt(&ciphertext, &cipher_key)
}

/// Returns the ciphertext and the sender's public key contained in message.
///
/// # Arguments
///
/// * `message` - message to be read
///
fn read_message(message: &Vec<u8>) -> (Vec<u8>, RistrettoPoint) {
    let ciphertext = read_ciphertext(message);
    let pbk = read_pbk(message);
    (ciphertext, pbk)
}

fn read_ciphertext(message: &Vec<u8>) -> Vec<u8> {
    message[0..(message.len() - 32)].to_vec()
}

fn read_pbk(message: &Vec<u8>) -> RistrettoPoint {
    let pbk = &message[(message.len() - 32)..message.len()];
    let pbk = <[u8; 32]>::try_from(pbk).unwrap();
    CompressedRistretto(pbk).decompress().unwrap()
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

        let shares = make_random_shares(secret, threshold, n_shares);
        let recov_secret = recover_secret(&shares, threshold);

        assert_eq!(secret, recov_secret);
    }

    #[test]
    fn encryption_decryption_test() {
        let mut csprng = OsRng;

        let original_text = b"plaintext message";
        let attribute_keypair = generate_keypair(&mut csprng);

        // Encryption process

        let attribute_pbk = attribute_keypair.1;
        let message = process_encryption(&mut csprng, original_text, &attribute_pbk);

        // Decryption process

        let attribute_pkc = attribute_keypair.0;
        let plaintext = process_decryption(&message, &attribute_pkc);

        assert_eq!(plaintext, original_text.to_vec());
    }
}
