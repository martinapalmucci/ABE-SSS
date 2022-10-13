use std::collections::HashMap;

use abe_sss::{
    chachapoly::{chacha20poly1305_decrypt, chacha20poly1305_encrypt},
    sss::Share,
    trees::{Node, PolicyNode},
    utils::generate_keypair,
};
use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::OsRng;

fn main() {
    // Set up system
    let keypairs = attribute_keypairs_example(); // every attribute key pair
    let every_pubkeys = public_keys_example(&keypairs); // every attribute public keys
    let my_seckeys = private_keys_example_1(&keypairs); // my attribute private keys

    // Resource encryption process
    let resource = "Welcome to ABE-SSS!"; // my database resource
    let policy_tree = policy_tree_example(); // its policy tree

    let dek = Scalar::random(&mut OsRng); // data encryption key (DEK)

    let enc_resource = chacha20poly1305_encrypt(dek.as_bytes(), resource.as_bytes()); // resource encryption

    // DEK encryption process
    let secret_share_0 = Share::new(Scalar::zero(), dek); // set up first share

    let share_tree = policy_tree.generate_encrypt_shares(&secret_share_0, &every_pubkeys); // encrypt
    let decrypted_share = share_tree.recover_secret_share(&policy_tree, &my_seckeys); // decrypt

    assert_eq!(
        secret_share_0.serialize(),
        decrypted_share.as_ref().unwrap().serialize()
    );

    // Resource dencryption process
    let decrypted_dek = decrypted_share.unwrap().get_secret();

    let decrypted_resource = chacha20poly1305_decrypt(decrypted_dek.as_bytes(), &enc_resource);

    assert_eq!(resource.as_bytes(), decrypted_resource);
}

/// Example of Policy Tree
fn policy_tree_example() -> Node<PolicyNode> {
    let leaf_r = Node {
        name: 5,
        value: PolicyNode::Leaf(String::from("attr_r")),
        children: vec![],
    };
    let leaf_s = Node {
        name: 6,
        value: PolicyNode::Leaf(String::from("attr_s")),
        children: vec![],
    };

    let branch = Node {
        name: 3,
        value: PolicyNode::Branch(1),
        children: vec![leaf_r, leaf_s],
    };

    let leaf_q = Node {
        name: 2,
        value: PolicyNode::Leaf(String::from("attr_q")),
        children: vec![],
    };
    let leaf_p = Node {
        name: 4,
        value: PolicyNode::Leaf(String::from("attr_p")),
        children: vec![],
    };

    Node {
        name: 1,
        value: PolicyNode::Branch(2),
        children: vec![leaf_q, branch, leaf_p],
    }
}

/// Example of attribute keypairs in the system
fn attribute_keypairs_example() -> HashMap<String, (Scalar, RistrettoPoint)> {
    let list_of_attributes = ["attr_r", "attr_s", "attr_p", "attr_q"];

    let mut attr_keypairs = HashMap::new();

    for attribute in list_of_attributes {
        let keypair = generate_keypair();
        attr_keypairs.insert(attribute.to_string(), keypair);
    }
    attr_keypairs
}

/// Example 1 of attribute PRIVATE keys the user has
fn private_keys_example_1(
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

/// Example 2 of attribute PRIVATE keys the user has
fn private_keys_example_2(
    keypairs: &HashMap<String, (Scalar, RistrettoPoint)>,
) -> HashMap<String, Scalar> {
    let list_attribute = ["attr_r"];

    let mut my_keys = HashMap::new();

    for attribute in list_attribute {
        let key = keypairs.get(attribute).unwrap().0;
        my_keys.insert(attribute.to_string(), key);
    }
    my_keys
}

/// Examples of every attribute PUBLIC key in the system
fn public_keys_example(
    keypairs: &HashMap<String, (Scalar, RistrettoPoint)>,
) -> HashMap<String, RistrettoPoint> {
    let mut my_keys = HashMap::new();
    for (attribute, keypair) in keypairs {
        my_keys.insert(attribute.to_string(), keypair.1);
    }
    my_keys
}
