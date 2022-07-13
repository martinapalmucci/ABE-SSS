use std::collections::HashMap;

use abe_sss::make_random_shares;
use curve25519_dalek_ng::scalar::Scalar;
use rand_core::OsRng;

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; // Or `XChaCha20Poly1305`

use curve25519_dalek_ng::constants;
use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};

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
fn generate_keypair(csprng: &mut OsRng) -> (Scalar, RistrettoPoint) {
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

fn write_ciphertext(ciphertext: &Vec<u8>) -> Vec<u8> {
    ciphertext.clone()
}

fn write_pbk(pbk: &RistrettoPoint) -> Vec<u8> {
    pbk.compress().to_bytes().to_vec()
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
fn process_encryption(plaintext: &[u8], pbk: &RistrettoPoint) -> Vec<u8> {
    let mut csprng = OsRng;
    let ephemeral_keypair = generate_keypair(&mut csprng);
    let (ephemeral_pkc, ephemeral_pbk) = ephemeral_keypair;

    let cipher_key = key_derivation_fn(&ephemeral_pkc, &pbk);
    let ciphertext = encrypt(plaintext, &cipher_key);

    write_message(&ciphertext, &ephemeral_pbk)
}

fn read_ciphertext(message: &Vec<u8>) -> Vec<u8> {
    message[0..(message.len() - 32)].to_vec()
}

fn read_pbk(message: &Vec<u8>) -> RistrettoPoint {
    let pbk = &message[(message.len() - 32)..message.len()];
    let pbk = <[u8; 32]>::try_from(pbk).unwrap();
    CompressedRistretto(pbk).decompress().unwrap()
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
fn process_decryption(message: &Vec<u8>, pkc: &Scalar) -> Vec<u8> {
    let (ciphertext, ephemeral_pbk) = read_message(&message);
    let cipher_key = key_derivation_fn(&pkc, &ephemeral_pbk);
    decrypt(&ciphertext, &cipher_key)
}

fn encryption_decryption_test() {
    let mut csprng = OsRng;

    let attribute_keypair = generate_keypair(&mut csprng);

    // Encryption process

    let original_text = b"plaintext message";
    let attribute_pbk = attribute_keypair.1;
    let message = process_encryption(original_text, &attribute_pbk);

    // Decryption process

    let attribute_pkc = attribute_keypair.0;
    let plaintext = process_decryption(&message, &attribute_pkc);

    assert_eq!(plaintext, original_text.to_vec());
}

fn main() {}

// GENERATE THE SECRET TREE
// First part of the project

#[derive(Debug, Clone)]
struct Node<T> {
    name: u32,
    value: T,
    children: Vec<Node<T>>,
}

impl Node<AttributeNode> {
    /// Returns a secret root of a secret tree.
    ///
    /// The structure of the returned secret tree is the same as the attribute tree with self as root.
    ///
    /// # Arguments
    ///
    /// * `self` - attribute root of attribute tree
    /// * `secret_point` - secret point of the secret root
    ///
    /// # Example
    ///
    /// ```
    /// let root = Node {
    ///     name: 1,  
    ///     value: AttributeNode::Leaf(String::from("attr_")),
    ///     children: vec![],
    /// };
    ///
    /// let secret_point = (Scalar::zero(), Scalar::one());
    /// let secret_root = root.generate_shares(&secret_point);
    /// ```
    pub fn generate_shares(&self, secret_point: &(Scalar, Scalar)) -> Node<(Scalar, Scalar)> {
        let mut list_children = vec![];

        if let AttributeNode::Branch(t) = self.value {
            let threshold = t;
            let n_shares = self.children.len();
            let (_, secret) = secret_point;

            let shares = make_random_shares(*secret, threshold, n_shares);

            for (child, share) in self.children.iter().zip(&shares) {
                let secret_child = child.generate_shares(share);
                list_children.push(secret_child);
            }
        }

        Node {
            name: self.name,
            value: secret_point.clone(),
            children: list_children,
        }
    }
}

#[derive(Debug, Clone)]
enum AttributeNode {
    Leaf(String),
    Branch(usize),
}

fn attribute_tree_example() -> Node<AttributeNode> {
    let leaf_r = Node {
        name: 5,
        value: AttributeNode::Leaf(String::from("attr_r")),
        children: vec![],
    };
    let leaf_s = Node {
        name: 6,
        value: AttributeNode::Leaf(String::from("attr_s")),
        children: vec![],
    };

    let branch = Node {
        name: 3,
        value: AttributeNode::Branch(1),
        children: vec![leaf_r, leaf_s],
    };

    let leaf_q = Node {
        name: 2,
        value: AttributeNode::Leaf(String::from("attr_q")),
        children: vec![],
    };
    let leaf_p = Node {
        name: 4,
        value: AttributeNode::Leaf(String::from("attr_p")),
        children: vec![],
    };

    Node {
        name: 1,
        value: AttributeNode::Branch(2),
        children: vec![leaf_q, branch, leaf_p],
    }
}

fn MAIN_secret_tree_generation() {
    let mut csprng = OsRng;

    let root = attribute_tree_example();

    //println!("Plain Text Tree =\n{:#?}", root);

    let secret = Scalar::random(&mut csprng);
    let secret_point = (Scalar::zero(), secret);

    let secret_root = root.generate_shares(&secret_point);

    //println!("Secret Tree =\n{:#?}", secret_root);
}

fn attribute_keypairs_example() -> HashMap<String, (Scalar, RistrettoPoint)> {
    let list_of_attributes = ["attr_r", "attr_s", "attr_p", "attr_q"];

    let mut attr_keypairs = HashMap::new();

    let mut csprng = OsRng;

    for attribute in list_of_attributes {
        let keypair = generate_keypair(&mut csprng);
        attr_keypairs.insert(attribute.to_string(), keypair);
    }
    attr_keypairs
}
