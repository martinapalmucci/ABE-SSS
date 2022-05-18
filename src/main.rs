use abe_sss::make_random_shares;
use curve25519_dalek_ng::scalar::Scalar;
use rand_core::OsRng;

#[derive(Debug)]
struct Node {
    name: u32,
    node_type: NodeType,
    children: Vec<Node>,
}

impl Node {
    fn new(name: u32, node_type: NodeType, children: Vec<Node>) -> Self {
        Node { name, node_type, children }
    }

    fn set_node_type(&mut self, nodetype: NodeType) -> &mut Self {
        self.node_type = nodetype;
        self
    }
}

#[derive(Debug)]
enum NodeType {
    AttributeNode(AttributeNodeType),
    SecretNode(Scalar),
}

#[derive(Debug)]
enum AttributeNodeType {
    Leaf(String),
    Branch(u32),
}

fn copy_tree(root: &Node) -> Node {
    /*  creates a secret tree based on another
        one whose root is the input argument
    */

    // check whether root is an AttributeNode or not

    let mut children_list: Vec<Node> = Vec::new();
    for node in &root.children {
        children_list.push(copy_tree(node));
    }

    Node {
        name: root.name,
        children: children_list,
        node_type: NodeType::SecretNode(Scalar::zero()),
    }
}



fn main() {
    /*  Example of Attribute Tree
        */
    let leaf_r = Node::new(
        5,
        NodeType::AttributeNode(AttributeNodeType::Leaf(String::from("attr_s"))),
        Vec::new()
    );
    let leaf_s = Node::new(
        6,
        NodeType::AttributeNode(AttributeNodeType::Leaf(String::from("attr_s"))),
        Vec::new()        
    );

    let branch = Node::new(
        3, 
        NodeType::AttributeNode(AttributeNodeType::Branch(1)),
        vec![leaf_r, leaf_s]
    );

    let leaf_q = Node::new(
        2,
        NodeType::AttributeNode(AttributeNodeType::Leaf(String::from("attr_q"))),
        Vec::new()
        
    );
    let leaf_p = Node::new(
        4,
        NodeType::AttributeNode(AttributeNodeType::Leaf(String::from("attr_p"))),
        Vec::new()        
    );

    let root = Node::new(
        1,
        NodeType::AttributeNode(AttributeNodeType::Branch(2)),
        vec![leaf_q, branch, leaf_p],
    );

    println!("Attribute Tree =\n{:#?}", root);

    /*  Example of Secret Tree
    */

    // main secret
    let mut csprng = OsRng;
    let secret = Scalar::random(&mut csprng);

    //println!("Main secret =\n{:#?}", secret);

    // secret tree
    let mut new_root = copy_tree(&root);
    
    new_root.set_node_type(NodeType::SecretNode(secret));

    // read tree and generate the relative shares
            //let threshold = 3; let n_shares = 6;
            //let shares = make_random_shares(secret, threshold, n_shares);

    println!("Secret tree =\n{:#?}", new_root);
}