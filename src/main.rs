use abe_sss::make_random_shares;
use curve25519_dalek_ng::scalar::Scalar;
use rand_core::OsRng;

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
    /// let mut csprng = OsRng;
    /// let secret_point = (Scalar::zero(), Scalar::random(&mut csprng));
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

fn main() {
    let root = example_tree();

    println!("Plain Text Tree =\n{:#?}", root);

    let mut csprng = OsRng;
    let secret = Scalar::random(&mut csprng);
    let secret_point = (Scalar::zero(), secret);

    let secret_root = root.generate_shares(&secret_point);

    println!("Secret Tree =\n{:#?}", secret_root);
}
