use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::OsRng;
use std::collections::HashMap;

use crate::{
    ecies::{ecies_decrypt, ecies_encrypt},
    sss::{Share, SSS},
    utils::generate_public_key,
};

#[derive(Debug, Clone)]
struct Node<T> {
    name: u32,
    value: T,
    children: Vec<Node<T>>,
}

#[derive(Debug, Clone)]
enum PolicyNode {
    Leaf(String),
    Branch(usize),
}

#[derive(Debug, Clone)]
pub struct ShareNode {
    pub encrypted_share: Vec<u8>,
}

impl Node<PolicyNode> {
    /// Generates the encrypted share tree.
    ///
    /// # Arguments
    ///
    /// * `secret_share` - Secret to split by SSS_making_share (if needed) and secure by ECIES_encrypt
    /// * `keypairs_pub` - An HashMap reference of attributes and their corresponding public key
    pub fn generate_encrypt_shares(
        &self,
        secret_share: &Share,
        keypairs_pub: &HashMap<String, RistrettoPoint>,
    ) -> Node<ShareNode> {
        let (ecies_receiver_pubkey, share_children) = match &self.value {
            PolicyNode::Branch(t) => {
                let ecies_receiver_seckey = Scalar::random(&mut OsRng);

                // output 1 : ecies receiver's public key
                let ecies_receiver_pubkey = generate_public_key(&ecies_receiver_seckey);

                // output 2 : encrypted shares
                let schema = SSS::new(*t, self.children.len()).unwrap();
                let shares = schema.make_random_shares(ecies_receiver_seckey);

                let mut share_children = vec![];
                for (policy_child, share) in self.children.iter().zip(&shares) {
                    let share_child = policy_child.generate_encrypt_shares(share, keypairs_pub);
                    share_children.push(share_child);
                }

                (ecies_receiver_pubkey, share_children)
            }
            PolicyNode::Leaf(a) => {
                // output 1 : ecies receiver's public key
                let ecies_receiver_pubkey = *keypairs_pub.get(a).unwrap(); // attribute public key

                // output 2 : encrypted shares
                let share_children = vec![];

                (ecies_receiver_pubkey, share_children)
            }
        };

        let share_value = ecies_encrypt(&secret_share.serialize_chain(), &ecies_receiver_pubkey);

        Node {
            name: self.name,
            value: ShareNode {
                encrypted_share: share_value,
            },
            children: share_children,
        }
    }
}

impl Node<ShareNode> {
    /// Recovers the secret share.
    ///
    /// # Arguments
    ///
    /// * `policy_root` - A Node<PolicyNode> referene of the policy tree
    /// * `keypairs_sec` - An HashMap reference of attributes and their corresponding private key
    pub fn recover_secret_share(
        &self,
        policy_root: &Node<PolicyNode>,
        keypairs_sec: &HashMap<String, Scalar>,
    ) -> Option<Share> {
        let ecies_receiver_seckey = match &policy_root.value {
            PolicyNode::Branch(threshold) => {
                let mut shares: Vec<Share> = Vec::new();
                let joined_trees_iter = self.children.iter().zip(&policy_root.children);
                for (share_child, policy_child) in joined_trees_iter {
                    let output = share_child.recover_secret_share(policy_child, keypairs_sec);
                    if let Some(share) = &output {
                        shares.push(share.clone());
                    }
                }
                match SSS::new(*threshold, shares.len()) {
                    Ok(sss_schema) => Some(sss_schema.recover_secret(&shares)),
                    _ => None,
                }
            }
            PolicyNode::Leaf(a) => keypairs_sec.get(a).copied(),
        };

        match ecies_receiver_seckey {
            Some(seckey) => {
                let ciphertext = &self.value.encrypted_share;
                let msg = ecies_decrypt(ciphertext, &seckey);
                Some(Share::parse_msg(&msg))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::generate_keypair;
    use rand_core::OsRng;

    #[test]
    fn encryption_decryption_test_1() {
        // Set system variables
        let keypairs = attribute_keypairs_example();
        let every_pubkeys = public_keys_example(&keypairs);

        // Set resource variables
        let policy_tree = policy_tree_example();
        let secret_share = Share::new(Scalar::zero(), Scalar::random(&mut OsRng));

        // Encrypt
        let encrypted_share_root =
            policy_tree.generate_encrypt_shares(&secret_share, &every_pubkeys);

        // Set user variables
        let my_seckeys = private_keys_example_1(&keypairs);

        // Decrypt
        let decrypted_secret_share =
            encrypted_share_root.recover_secret_share(&policy_tree, &my_seckeys);

        assert_eq!(
            secret_share.serialize(),
            decrypted_secret_share.unwrap().serialize()
        );
    }

    #[test]
    #[should_panic]
    fn encryption_decryption_test_2() {
        // Set system variables
        let keypairs = attribute_keypairs_example();
        let every_pubkeys = public_keys_example(&keypairs);

        // Set resource variables
        let policy_tree = policy_tree_example();
        let secret_share = Share::new(Scalar::zero(), Scalar::random(&mut OsRng));

        // Encrypt
        let encrypted_share_root =
            policy_tree.generate_encrypt_shares(&secret_share, &every_pubkeys);

        // Set user variables
        let my_seckeys = private_keys_example_2(&keypairs);

        // Decrypt
        let decrypted_secret_share =
            encrypted_share_root.recover_secret_share(&policy_tree, &my_seckeys);

        assert_eq!(
            secret_share.serialize(),
            decrypted_secret_share.unwrap().serialize()
        );
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
}
