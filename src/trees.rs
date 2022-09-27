use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar};
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
    pub encrypted: Vec<u8>,
}

impl Node<PolicyNode> {
    /// Generates the encrypted share tree.
    ///
    /// # Arguments
    ///
    /// * `secret_share` - Secret to split by SSS_making_share (if needed) and secure by ECIES_encrypt
    /// * `keypairs_pub` - An HashMap reference of attributes and their corresponding public key
    pub fn gen_encrypted_shares(
        &self,
        secret_share: &Share,
        keypairs_pub: &HashMap<String, RistrettoPoint>,
    ) -> Node<ShareNode> {
        let pubkey = match &self.value {
            PolicyNode::Branch(_) => generate_public_key(&secret_share.serialize().1), // derived public key
            PolicyNode::Leaf(a) => *keypairs_pub.get(a).unwrap(), // attribute public key
        };
        let mut list_children = vec![];
        if let PolicyNode::Branch(t) = &self.value {
            let schema = SSS::new(*t, self.children.len()).unwrap();
            let shares = schema.make_random_shares(secret_share.serialize().1);
            for (policy_node, share) in self.children.iter().zip(&shares) {
                let secret_child = policy_node.gen_encrypted_shares(share, keypairs_pub);
                list_children.push(secret_child);
            }
        };
        Node {
            name: self.name,
            value: ShareNode {
                encrypted: ecies_encrypt(&secret_share.serialize_chain(), &pubkey),
            },
            children: list_children,
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
        match &policy_root.value {
            PolicyNode::Branch(threshold) => {
                let mut shares: Vec<Share> = Vec::new();
                let joined_trees_iter = self.children.iter().zip(&policy_root.children);
                for (share_node, policy_node) in joined_trees_iter {
                    let out = share_node.recover_secret_share(policy_node, keypairs_sec);
                    if let Some(share) = &out {
                        shares.push(share.clone());
                    }
                }
                let schema = SSS::new(*threshold, shares.len());
                match schema {
                    Ok(sss) => {
                        let msg =
                            ecies_decrypt(&self.value.encrypted, &sss.recover_secret(&shares));
                        Some(Share::parse_msg(&msg))
                    }
                    _ => None,
                }
            }
            PolicyNode::Leaf(a) => match keypairs_sec.get(a) {
                Some(attribute_seckey) => {
                    let msg = ecies_decrypt(&self.value.encrypted, attribute_seckey);
                    Some(Share::parse_msg(&msg))
                }
                _ => None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use crate::utils::generate_keypair;

    use super::*;

    #[test]
    fn encryption_decryption_test_1() {
        // Set system variables
        let keypairs = attribute_keypairs_example();
        let every_pubkeys = public_keys_example(&keypairs);

        // Set resource variables
        let policy_tree = policy_tree_example();
        let secret_share = Share::new(Scalar::zero(), Scalar::random(&mut OsRng));

        // Encrypt
        let encrypted_share_root = policy_tree.gen_encrypted_shares(&secret_share, &every_pubkeys);

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
        let encrypted_share_root = policy_tree.gen_encrypted_shares(&secret_share, &every_pubkeys);

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
