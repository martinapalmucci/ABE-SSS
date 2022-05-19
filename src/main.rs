use std::collections::VecDeque;

use abe_sss::make_random_shares;
use curve25519_dalek_ng::scalar::Scalar;
use rand_core::OsRng;

#[derive(Debug, Clone)]
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

    fn set_children(&mut self, children: Vec<Node>) {
        self.children = children;
    }
}

#[derive(Debug, Clone)]
enum NodeType {
    AttributeNode(AttributeNodeType),
    SecretNode((Scalar, Scalar)),
}

#[derive(Debug, Clone)]
enum AttributeNodeType {
    Leaf(String),
    Branch(usize),
}

// Deep First Search (DFS) algorithm
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
        node_type: NodeType::SecretNode((Scalar::zero(), Scalar::zero())),
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

    //println!("Attribute Tree =\n{:#?}", root);



    /*  Example of Secret Tree
        >> Breadth First Search (BFS) algorithm <<
    */

    fn create_secret_tree(root: &Node) -> Node {

        // If the attribute root exists

        // Step 0:

            // Create a secret root with name, 
            // note_type but no childret yet

        let mut csprng = OsRng;
        let secret = Scalar::random(&mut csprng);

        let mut secret_root = Node {
            name: root.name,
            children: Vec::new(),
            node_type: NodeType::SecretNode((Scalar::zero(), secret)),
        };

            // Initialize two queues, one for the attribute tree and one for the secret tree, to establish 
            // the Breadth First Search (BFR) order to visit the nodes.

            // At first, push back both roots in the queues.
        
        let mut queue_attr = VecDeque::from([root]);
        let mut queue_secr = VecDeque::from([secret_root]);

        // Iterative Step:

            // While the queues are not empty,
            // visit the attributes nodes according to the attribute_queue order
            // and, at the same time, create the equivalent secret nodes in the
            // secret tree.

        while queue_attr.is_empty() == false && queue_secr.is_empty() == false {

            // Take the front node in the attribute queue, and
            // take the front node in the secret queue.
            // We will use it now so, we can pop them from the queues. 
    
            let front_attr = queue_attr.pop_front().unwrap();
            let mut front_secr = queue_secr.pop_front().unwrap();
    
            // If the front attribute node is a leaf, the iterative step is ended.
            // Else if the front attribute node is a branch, let us proceed.
    
            let type_front_attr = &front_attr.node_type;
            if let NodeType::AttributeNode(AttributeNodeType::Branch(t)) = type_front_attr {
    
                // Get number of shares and threshold from the front attribute node, and
                // get the main secret from the front secret node.
                // Then, use Shamir's Secret Sharing to make the random shares.
    
                let n_shares = front_attr.children.len();
                let threshold = t;
    
                let mut secret = Scalar::zero();
                let type_front_secr = &front_secr.node_type;
                if let NodeType::SecretNode((_, y_share)) = type_front_secr {
                    secret = *y_share;
                }
    
                let shares = make_random_shares(secret, *threshold, n_shares);
    
                // Once we have all the information to create the children of the front secret node,
                // create them. Also, push back them in the secret queue. Push back the equivalent
                // attribute children in the attribute queue as well.
    
                let mut children_secr_list: Vec<Node> = Vec::new();
                for (child_attr, share) in front_attr.children.iter().zip(&shares) {
                  
                    let child_secr = Node {
                        name: child_attr.name,
                        children: Vec::new(),
                        node_type: NodeType::SecretNode(*share),
                    };
                    children_secr_list.push(child_secr);
                }
                front_secr.set_children(children_secr_list); 

                for (child_attr, child_secr) in front_attr.children.iter().zip(&front_secr.children) {
                    queue_attr.push_back(child_attr);
                    queue_secr.push_back(child_secr);
                }
            }
        }
        secret_root
    }

    let secret_root = create_secret_tree(&root);
    println!("Secret Tree =\n{:#?}", secret_root);

}