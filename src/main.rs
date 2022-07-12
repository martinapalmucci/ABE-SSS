use abe_sss::make_random_shares;
use curve25519_dalek_ng::scalar::Scalar;
use rand_core::OsRng;

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; // Or `XChaCha20Poly1305`

use curve25519_dalek_ng::constants;
use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};

use std::collections::HashMap;
use std::str;

fn generate_keypair(csprng: &mut OsRng) -> (Scalar, RistrettoPoint) {
    let private_key = Scalar::random(csprng);
    let public_key = &private_key * &constants::RISTRETTO_BASEPOINT_TABLE;
    (private_key, public_key)
}

fn example_keypairs() -> HashMap<String, (Scalar, RistrettoPoint)> {
    let list_of_attributes = ["attr_r", "attr_s", "attr_p", "attr_q"];

    let mut attr_keypairs = HashMap::new();

    let mut csprng = OsRng;

    for attribute in list_of_attributes {
        let keypair = generate_keypair(&mut csprng);
        attr_keypairs.insert(attribute.to_string(), keypair);
    }
    attr_keypairs
}

fn main() {
    let mut csprng = OsRng;

    // Create an example with attribute keypairs as hash map.
    // The example attributes are:
    //  - attr_r
    //  - attr_s
    //  - attr_p
    //  - attr_q

    let attr_keypairs = example_keypairs();

    // Let's try encryption and decreption the attribute "attr_r".

    let an_attr = "attr_r";

    // Get private (x) and public (X) keys related to the attribute attr_r

    let (x, X) = attr_keypairs.get(an_attr).unwrap();

    // Generate a random number (r) and a random point (R) to use in the process

    let (r, R) = generate_keypair(&mut csprng);

    // ENCRYPTION

    fn get_cipher_key(scalar: &Scalar, point: &RistrettoPoint) -> CompressedRistretto {
        let cipher_key = (scalar * point).compress();
        cipher_key
    }

    // Initialize the cipher with its key
    // using random number (r) and public attribute key (X) information

    let cipher_key = get_cipher_key(&r, X);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(cipher_key.as_bytes()));

    // Get the nonce

    let nonce = b"unique nonce"; // I used this for now.
                                 // However, I would like to add R into the nonce value
                                 //
                                 // something like:
                                 //
                                 // fn get_nonce(point: &RistrettoPoint) -> &[u8] {
                                 //     let nonce = point.compress().as_bytes();
                                 //     nonce.get(0..12).unwrap() // 12-bytes; unique per message
                                 // }
                                 //
                                 // let nonce = get_nonce(&R);
                                 //
                                 // or maybe ad hash function from 32 bytes to 12 bytes

    // Define the message to be encrypted

    let original_msg = "plaintext message";

    // Encrypt the message

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(nonce), original_msg.as_bytes().as_ref())
        .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

    // DECRYPTION

    // Initialize the cipher with its key
    // using private attribute key (x) and random point (R) information

    let cipher_key = get_cipher_key(x, &R);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(cipher_key.as_bytes()));

    // Get the nonce

    let nonce = b"unique nonce"; // to be changed with random point (R) information.
                                 // Look at nonce in encryption section.

    // Decrypt the ciphertext

    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext.as_ref())
        .expect("decryption failure!"); // NOTE: handle this error to avoid panics!

    // Check if original message and decrypted message are the same

    let plaintext_msg = str::from_utf8(&plaintext).unwrap();
    assert_eq!(original_msg, plaintext_msg);
}

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
    /// # Arguments
    ///
    /// * `self` - plain text root of plain text tree
    /// * `secret_point` - secret point of the root
    ///
    /// # Example
    ///
    /// ```
    /// // If "root" is a Node<AttributeNode> and a root of a plain text tree,
    /// let root = Node {
    ///     name: 1,  
    ///     value: AttributeNode::Leaf(String::from("attr_")),
    ///     children: vec![],
    /// };
    /// // you can generate randomly the first secret point, e.g.
    /// let secret_point = (Scalar::zero(), Scalar::one());
    /// // and then, generate the secret tree from the plain text tree
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

fn example_tree() -> Node<AttributeNode> {
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

    let root = example_tree();

    //println!("Plain Text Tree =\n{:#?}", root);

    let secret = Scalar::random(&mut csprng);
    let secret_point = (Scalar::zero(), secret);

    let secret_root = root.generate_shares(&secret_point);

    //println!("Secret Tree =\n{:#?}", secret_root);
}
