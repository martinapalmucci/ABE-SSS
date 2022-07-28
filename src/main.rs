use abe_sss::{
    concat_arrays, generate_keypair, make_random_shares, process_decryption, process_encryption,
    recover_secret,
};
use curve25519_dalek_ng::{constants, ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::OsRng;

use std::{collections::HashMap, error::Error, vec};

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
    /// * `csprng` - cryptographically secure pseudorandom number generator
    ///
    /// # Example
    ///
    /// ```
    /// let mut csprng = OsRng;
    ///
    /// let root = Node {
    ///     name: 1,  
    ///     value: AttributeNode::Leaf(String::from("attr_")),
    ///     children: vec![],
    /// };
    ///
    /// let secret_point = (Scalar::zero(), Scalar::one());
    /// let secret_root = root.generate_shares(&secret_point, &mut csprng);
    /// ```
    pub fn generate_shares(&self, secret_point: &(Scalar, Scalar)) -> Node<SecretNode> {
        let mut list_children = vec![];

        if let AttributeNode::Branch(t) = self.value {
            let shares = make_random_shares(secret_point.1, t, self.children.len());

            for (child, share) in self.children.iter().zip(&shares) {
                let secret_child = child.generate_shares(share);
                list_children.push(secret_child);
            }
        }

        Node {
            name: self.name,
            value: SecretNode::Plain(secret_point.clone()),
            children: list_children,
        }
    }

    pub fn generate_shares_and_encrypt(
        &self,
        secret_point: &(Scalar, Scalar),
        publickeypairs: &HashMap<String, RistrettoPoint>,
    ) -> Node<SecretNode> {
        let mut list_children = vec![];

        match &self.value {
            AttributeNode::Branch(t) => {
                let shares = make_random_shares(secret_point.1, *t, self.children.len());

                for (child, share) in self.children.iter().zip(&shares) {
                    let secret_child = child.generate_shares_and_encrypt(share, publickeypairs);
                    list_children.push(secret_child);
                }

                let concat_secret =
                    concat_arrays(secret_point.0.to_bytes(), secret_point.1.to_bytes());

                let private_key = secret_point.1;
                let generator = constants::RISTRETTO_BASEPOINT_TABLE;
                let public_key = &private_key * &generator;
                let encoded_secret = process_encryption(&concat_secret, &public_key);
                Node {
                    name: self.name,
                    value: SecretNode::Encoded(encoded_secret),
                    children: list_children,
                }
            }
            AttributeNode::Leaf(a) => {
                let concat_secret =
                    concat_arrays(secret_point.0.to_bytes(), secret_point.1.to_bytes());
                let attr_pbk = publickeypairs.get(a).unwrap();
                let encoded_secret = process_encryption(&concat_secret, attr_pbk);
                Node {
                    name: self.name,
                    value: SecretNode::Encoded(encoded_secret),
                    children: list_children,
                }
            }
        }
    }
}

impl Node<SecretNode> {
    pub fn encode(&mut self, attribute_pbk: &RistrettoPoint) {
        if let SecretNode::Plain(share) = self.value {
            let concat_share = concat_arrays(share.0.to_bytes(), share.1.to_bytes());
            let encoded_share = process_encryption(&concat_share, &attribute_pbk);
            self.value = SecretNode::Encoded(encoded_share);
        }
    }

    pub fn decode(&self, attribute_pkc: &Scalar) -> Node<SecretNode> {
        match &self.value {
            SecretNode::Encoded(message) => {
                let plain_share = process_decryption(&message, attribute_pkc).unwrap();
                let (plain_share_x, plain_share_y) = plain_share.split_at(32);
                let plain_share_x = Scalar::from_bits(<[u8; 32]>::try_from(plain_share_x).unwrap());
                let plain_share_y = Scalar::from_bits(<[u8; 32]>::try_from(plain_share_y).unwrap());

                Node {
                    name: self.name,
                    value: SecretNode::Plain((plain_share_x, plain_share_y)),
                    children: self.children.clone(),
                }
            }
            SecretNode::Plain(_) => self.clone(),
        }
    }

    /// Ritorna soltanto la radice modificata, il resto rimane cifrato
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

                if t <= &shares.len() {
                    let secret = recover_secret(&shares, *t);
                    self.decode(&secret)
                } else {
                    self.clone() //println!("No attribute to decrypt. Can't do anything."),
                }
            }
            AttributeNode::Leaf(a) => {
                match privatekeypairs.get(a) {
                    Some(private_key) => self.decode(private_key),
                    _ => self.clone(), //println!("No attribute to decrypt. Can't do anything."),
                }
            }
        }
    }

    /// Trascrive tutti i risultati sul nuovo albero
    pub fn recover_shares_and_decrypt_2(
        &self,
        privatekeypairs: &HashMap<String, Scalar>,
        attribute_root: &Node<AttributeNode>,
    ) -> Node<SecretNode> {
        match &attribute_root.value {
            AttributeNode::Branch(t) => {
                let mut list_children = vec![];
                for (child, attr_child) in self.children.iter().zip(&attribute_root.children) {
                    let new_child = child.recover_shares_and_decrypt_2(privatekeypairs, attr_child);
                    list_children.push(new_child);
                }

                let mut shares: Vec<(Scalar, Scalar)> = Vec::new();
                for child in &list_children {
                    if let SecretNode::Plain(share) = &child.value {
                        shares.push(*share);
                    }
                }

                if t <= &shares.len() {
                    let secret = recover_secret(&shares, *t);
                    Node {
                        name: self.name,
                        value: self.decode(&secret).value,
                        children: list_children,
                    }
                } else {
                    Node {
                        name: self.name,
                        value: self.value.clone(),
                        children: list_children,
                    }
                }
            }
            AttributeNode::Leaf(a) => match privatekeypairs.get(a) {
                Some(private_key) => self.decode(private_key),
                None => self.clone(),
            },
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
    Encoded(Vec<u8>),
}

fn main() {
    let mut csprng = OsRng;

    let root = attribute_tree_example();
    //println!("Plain Text Tree =\n{:#?}", root);

    let secret = Scalar::random(&mut csprng);
    let secret_point = (Scalar::zero(), secret);

    // let secret_root = root.generate_shares(&secret_point);
    // println!("Plain secret Tree =\n{:#?}", secret_root);

    let keypairs = attribute_keypairs_example();
    let my_pkc = private_keys_example(&keypairs);
    let my_pbk = public_keys_example(&keypairs);

    let secret_root = root.generate_shares_and_encrypt(&secret_point, &my_pbk);
    // println!("Secret Tree =\n{:#?}", secret_root);

    let dec_secret_root = secret_root.recover_shares_and_decrypt(&my_pkc, &root);
    // println!("Secret Tree =\n{:#?}", dec_secret_root);

    if let SecretNode::Plain(point) = dec_secret_root.value {
        assert_eq!(secret_point, point);
    } else {
        println!("Cannot confront. Error.")
    }

    let dec_secret_root_2 = secret_root.recover_shares_and_decrypt_2(&my_pkc, &root);
    // println!("Secret Tree =\n{:#?}", dec_secret_root_2);

    if let SecretNode::Plain(point) = dec_secret_root_2.value {
        assert_eq!(secret_point, point);
    } else {
        println!("Cannot confront. Error.")
    }
}

// nodi = 5 sì, 3 sì, 4 sì, 1 sì dovrebbero essere visibili. 6 no ok, 2 no ok

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

fn private_keys_example(
    keypairs: &HashMap<String, (Scalar, RistrettoPoint)>,
) -> HashMap<String, Scalar> {
    let list_attribute = ["attr_r", "attr_p"];

    let mut my_keys = HashMap::new();

    for attribute in list_attribute {
        let key = keypairs.get(attribute).unwrap().0;
        my_keys.insert(attribute.to_string(), key);
    }
    my_keys
}

fn public_keys_example(
    keypairs: &HashMap<String, (Scalar, RistrettoPoint)>,
) -> HashMap<String, RistrettoPoint> {
    let mut my_keys = HashMap::new();
    for (attribute, keypair) in keypairs {
        my_keys.insert(attribute.to_string(), keypair.1);
    }
    my_keys
}

fn plain_node_example() -> Node<SecretNode> {
    Node {
        name: 1,
        value: SecretNode::Plain((Scalar::default(), Scalar::default())),
        children: vec![],
    }
}

fn encoded_node_example() -> Node<SecretNode> {
    let pbk = RistrettoPoint::default();
    let mut mynode = plain_node_example();
    mynode.encode(&pbk);
    mynode
}

fn TRIAL_concat_and_split_arrays() {
    // Scrivre una funzione che presi due scalari li trasforma in un unica slice
    // e poi fare il viceversa
    let a = Scalar::zero();
    let b = Scalar::zero();

    let mut c: Vec<u8> = Vec::new();
    c.extend_from_slice(a.as_bytes());
    c.extend_from_slice(b.as_bytes());

    // Scalar::from_bits(<[u8; 64]>::try_from(c).unwrap());

    let (a_, b_) = c.split_at(32);
    let a_1 = Scalar::from_bits(<[u8; 32]>::try_from(a_).unwrap());
    let b_1 = Scalar::from_bits(<[u8; 32]>::try_from(b_).unwrap());

    assert_eq!((a, b), (a_1, b_1));

    // concat arrays

    let a = Scalar::zero().to_bytes();
    let b = Scalar::one().to_bytes();
    let c = concat_arrays(a, b);

    // println!("a = {:#?}", a);
    // println!("b = {:#?}", b);
    // println!("c = {:#?}", c);

    let (a, b) = c.split_at(32);
}
