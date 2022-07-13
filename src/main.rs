use abe_sss::make_random_shares;
use curve25519_dalek_ng::scalar::Scalar;
use rand_core::OsRng;

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; // Or `XChaCha20Poly1305`

use curve25519_dalek_ng::constants;
use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};

fn generate_keypair(csprng: &mut OsRng) -> (Scalar, RistrettoPoint) {
    let private_key = Scalar::random(csprng);
    let public_key = &private_key * &constants::RISTRETTO_BASEPOINT_TABLE;
    (private_key, public_key)
}

fn main() {
    // Before the encryption / decryption system

    let mut csprng = OsRng;
    let attribute_keypair = generate_keypair(&mut csprng);

    // Encryption process

    let attribute_pbk = attribute_keypair.1;

    let ephemeral_keypair = generate_keypair(&mut csprng);
    //let (ephemeral_pkc, ephemeral_pbk) = ephemeral_keypair;

    fn KDF(pkc: &Scalar, pbk: &RistrettoPoint) -> [u8; 32] {
        (pkc * pbk).compress().to_bytes()
    }

    let ephemeral_pkc = ephemeral_keypair.0;
    let cipher_key = KDF(&ephemeral_pkc, &attribute_pbk);

    fn encrypt(plaintext: &[u8], cipher_key: &[u8; 32]) -> Vec<u8> {
        let key = Key::from_slice(cipher_key);
        let cipher = ChaCha20Poly1305::new(key);

        let ciphertext = cipher
            .encrypt(&Nonce::default(), plaintext.as_ref())
            .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

        ciphertext
    }

    let original_text = b"plaintext message";
    let ciphertext = encrypt(original_text, &cipher_key);

    fn write_ciphertext(ciphertext: &Vec<u8>) -> Vec<u8> {
        ciphertext.clone()
    }

    fn write_pbk(pbk: &RistrettoPoint) -> Vec<u8> {
        pbk.compress().to_bytes().to_vec()
    }

    fn write_message(ciphertext: &Vec<u8>, pbk: &RistrettoPoint) -> Vec<u8> {
        let mut message: Vec<u8> = Vec::new();
        message.append(&mut write_ciphertext(ciphertext));
        message.append(&mut write_pbk(pbk));
        message
    }

    let ephemeral_pbk = ephemeral_keypair.1;

    let message = write_message(&ciphertext, &ephemeral_pbk);

    assert_eq!(
        message.len(),
        write_ciphertext(&ciphertext).len() + write_pbk(&ephemeral_pbk).len()
    );

    // Decryption process

    let attribute_pkc = attribute_keypair.0;

    fn read_ciphertext(message: &Vec<u8>) -> Vec<u8> {
        message[0..(message.len() - 32)].to_vec()
    }

    fn read_pbk(message: &Vec<u8>) -> RistrettoPoint {
        let pbk = &message[(message.len() - 32)..message.len()];
        let pbk = <[u8; 32]>::try_from(pbk).unwrap();
        CompressedRistretto(pbk).decompress().unwrap()
    }

    fn read_message(message: &Vec<u8>) -> (Vec<u8>, RistrettoPoint) {
        let ciphertext = read_ciphertext(message);
        let pbk = read_pbk(message);
        (ciphertext, pbk)
    }

    let (ciphertext, ephemeral_pbk) = read_message(&message);

    let cipher_key = KDF(&attribute_pkc, &ephemeral_pbk);

    fn decrypt(ciphertext: &[u8], cipher_key: &[u8; 32]) -> Vec<u8> {
        let key = Key::from_slice(cipher_key);
        let cipher = ChaCha20Poly1305::new(key);

        let plaintext = cipher
            .decrypt(&Nonce::default(), ciphertext.as_ref())
            .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

        plaintext
    }

    let plaintext = decrypt(&ciphertext, &cipher_key);

    assert_eq!(plaintext, original_text.to_vec())
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
