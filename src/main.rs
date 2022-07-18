use abe_sss::make_random_shares;
use curve25519_dalek_ng::scalar::Scalar;
use rand_core::OsRng;

use std::vec;

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
    pub fn generate_shares(
        &self,
        secret_point: &(Scalar, Scalar),
        csprng: &mut OsRng,
    ) -> Node<(Scalar, Scalar)> {
        let mut list_children = vec![];

        if let AttributeNode::Branch(t) = self.value {
            let threshold = t;
            let n_shares = self.children.len();
            let (_, secret) = secret_point;

            let shares = make_random_shares(csprng, *secret, threshold, n_shares);

            for (child, share) in self.children.iter().zip(&shares) {
                let secret_child = child.generate_shares(share, csprng);
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

fn main() {
    let mut csprng = OsRng;

    let root = attribute_tree_example();

    //println!("Plain Text Tree =\n{:#?}", root);

    let secret = Scalar::random(&mut csprng);
    let secret_point = (Scalar::zero(), secret);

    let secret_root = root.generate_shares(&secret_point, &mut csprng);

    //println!("Secret Tree =\n{:#?}", secret_root);
}

// fn attribute_keypairs_example() -> HashMap<String, (Scalar, RistrettoPoint)> {
//     let list_of_attributes = ["attr_r", "attr_s", "attr_p", "attr_q"];

//     let mut attr_keypairs = HashMap::new();

//     let mut csprng = OsRng;

//     for attribute in list_of_attributes {
//         let keypair = generate_keypair(&mut csprng);
//         attr_keypairs.insert(attribute.to_string(), keypair);
//     }
//     attr_keypairs
// }
