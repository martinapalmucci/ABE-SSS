use abe_sss::{
    chain_point, generate_keypair, generate_public_key, make_random_shares, process_decryption,
    process_encryption, read_message, recover_secret, write_message,
};
use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::OsRng;

use std::{collections::HashMap, vec};

#[derive(Debug, Clone)]
struct Node<T> {
    name: u32,
    value: T,
    children: Vec<Node<T>>,
}

impl Node<AttributeNode> {
    /// Generates the secret tree and
    /// encrypts every node with the correct public key
    pub fn generate_encrypted_shares(
        &self,
        secret_point: &(Scalar, Scalar),
        public_keypairs: &HashMap<String, RistrettoPoint>,
    ) -> Node<SecretNode> {
        let mut list_children = vec![];

        if let AttributeNode::Branch(t) = &self.value {
            let shares = make_random_shares(secret_point.1, *t, self.children.len()).unwrap();
            for (child, share) in self.children.iter().zip(&shares) {
                let secret_child = child.generate_encrypted_shares(share, public_keypairs);
                list_children.push(secret_child);
            }
        };

        let new_node = Node {
            name: self.name,
            value: SecretNode::Plain(*secret_point),
            children: list_children,
        };

        let pbk = match &self.value {
            AttributeNode::Branch(_) => generate_public_key(&secret_point.1), // derived public key
            AttributeNode::Leaf(a) => *public_keypairs.get(a).unwrap(), // attribute public key
        };

        new_node.encrypt(&pbk)
    }
}

impl Node<SecretNode> {
    pub fn encrypt(&self, pbk: &RistrettoPoint) -> Node<SecretNode> {
        match &self.value {
            SecretNode::Plain(share) => {
                let (encrypted_share, ephemeral_pbk) =
                    process_encryption(&chain_point(share), &pbk);
                let message = write_message(&encrypted_share, &ephemeral_pbk);

                Node {
                    name: self.name,
                    value: SecretNode::Encrypted(message),
                    children: self.children.clone(),
                }
            }
            SecretNode::Encrypted(_) => self.clone(),
        }
    }

    pub fn decrypt(&self, pkc: &Scalar) -> Node<SecretNode> {
        match &self.value {
            SecretNode::Encrypted(message) => {
                let (ciphertext, pbk) = read_message(message);
                let plain_share = process_decryption(ciphertext, &pbk.unwrap(), pkc);
                let plain_share = plain_share.split_at(32);
                let plain_share_0 = Scalar::from_bits(<[u8; 32]>::try_from(plain_share.0).unwrap());
                let plain_share_1 = Scalar::from_bits(<[u8; 32]>::try_from(plain_share.1).unwrap());

                Node {
                    name: self.name,
                    value: SecretNode::Plain((plain_share_0, plain_share_1)),
                    children: self.children.clone(),
                }
            }
            SecretNode::Plain(_) => self.clone(),
        }
    }

    /// The secret tree is partially reconstruct.
    /// Only the secret root is available.
    pub fn recover_shares_and_decrypt(
        &self,
        privatekeypairs: &HashMap<String, Scalar>,
        attribute_root: &Node<AttributeNode>,
    ) -> Node<SecretNode> {
        match &attribute_root.value {
            AttributeNode::Branch(t) => {
                let mut shares: Vec<(Scalar, Scalar)> = Vec::new();
                for (child, attr_child) in self.children.iter().zip(&attribute_root.children) {
                    let new_child = child.recover_shares_and_decrypt(privatekeypairs, attr_child);
                    if let SecretNode::Plain(share) = &new_child.value {
                        shares.push(*share);
                    }
                }

                match recover_secret(&shares, *t) {
                    Ok(secret) => self.decrypt(&secret),
                    Err(_) => self.clone(),
                }
            }
            AttributeNode::Leaf(a) => {
                match privatekeypairs.get(a) {
                    Some(private_key) => self.decrypt(private_key),
                    _ => self.clone(), //println!("No attribute to decrypt. Can't do anything."),
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
enum AttributeNode {
    Leaf(String),
    Branch(usize),
}

#[derive(Debug, Clone)]
enum SecretNode {
    Plain((Scalar, Scalar)),
    Encrypted(Vec<u8>),
}

fn main() {
    let mut csprng = OsRng;

    // println!("The attribute tree is generated.");
    let root = attribute_tree_example();
    // println!("Attribute Tree =\n{:#?}", root);

    // println!("Set a key k_0 as secret.");
    let secret = Scalar::random(&mut csprng);
    let secret_point = (Scalar::zero(), secret);

    // println!("The plain secret tree is generated.");
    // let secret_root = root.generate_shares(&secret_point);
    // println!("Plain secret Tree =\n{:#?}", secret_root);

    // println!("Set every attribute keypairs.");
    let keypairs = attribute_keypairs_example();

    // println!("Generate and encrypt the secret tree.");
    let my_pbk = public_keys_example(&keypairs);
    let secret_root = root.generate_encrypted_shares(&secret_point, &my_pbk);
    // println!("Secret Tree =\n{:#?}", secret_root);

    // println!("Partially reconstruct the secret tree.");
    // println!("Only the secret root must be available.");
    let my_pkc = private_keys_example(&keypairs);
    let dec_secret_root = secret_root.recover_shares_and_decrypt(&my_pkc, &root);
    // println!("Secret Tree =\n{:#?}", dec_secret_root);

    if let SecretNode::Plain(point) = dec_secret_root.value {
        assert_eq!(secret_point, point);
    } else {
        println!("Cannot confront. Error.")
    }
}

/// Example of
/// Attribute tree
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

/// Example of
/// Attribute keypairs in the system
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

/// Example of
/// Attribute PRIVATE keys the user has
fn private_keys_example(
    keypairs: &HashMap<String, (Scalar, RistrettoPoint)>,
) -> HashMap<String, Scalar> {
    let list_attribute = ["attr_r", "attr_p"];
    //let list_attribute = ["attr_r"];

    let mut my_keys = HashMap::new();

    for attribute in list_attribute {
        let key = keypairs.get(attribute).unwrap().0;
        my_keys.insert(attribute.to_string(), key);
    }
    my_keys
}

/// Examples of
/// Every attribute PUBLIC key in the system
fn public_keys_example(
    keypairs: &HashMap<String, (Scalar, RistrettoPoint)>,
) -> HashMap<String, RistrettoPoint> {
    let mut my_keys = HashMap::new();
    for (attribute, keypair) in keypairs {
        my_keys.insert(attribute.to_string(), keypair.1);
    }
    my_keys
}
