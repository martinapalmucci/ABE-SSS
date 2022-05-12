use abe_sss::lagrange_interpolate;
use curve25519_dalek_ng::scalar::Scalar;
use rand_core::OsRng;
use polynomials::{Polynomial, poly};


#[derive(Debug)]
struct Node {
    name: u32,
    node_type: NodeType,
    children: Vec<Node>,
}

impl Node {

    fn new(name: u32, children: Vec<Node>, node_type: NodeType) -> Self {
        Node {
            name,
            children,
            node_type  
        }
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

    let mut children_list : Vec<Node> = Vec::new();
    for node in root.children.iter(){
        children_list.push(copy_tree(node))
    }

    let copied_root = Node { 
        name: root.name, 
        children: children_list, 
        node_type: NodeType::SecretNode(Scalar::zero()) 
    };

    copied_root
}


fn generate_random_polynomial(a_0: Scalar, degree: u32) -> Polynomial<Scalar> {
    /*  generates a random polynomial with 
        costant term "a_0" and degree "degree"
     */

    let mut csprng = OsRng;

    let mut p = poly![a_0];

    for _ in 0..(degree - 1) {
        let a_i = Scalar::random(&mut csprng); 
        p.push(a_i)
    }

    p
}


fn generate_random_vector(length: u32) -> Vec<Scalar> {
    /*  generates a random vector with 
        "length" number of elements
    */
    let mut csprng = OsRng;

    let mut vec: Vec<Scalar> = Vec::new();

    for _ in 0..length {
        let v_i = Scalar::random(&mut csprng);
        vec.push(v_i)
    }

    vec
}

fn evaluate_polynomial(p: Polynomial<Scalar>, x: Vec<Scalar>) -> Vec<Scalar> {
    /*  returns the y-coordinates evaluated on a 
        polinomial "p" in the x-coordinates "x"   
    */

    let mut y: Vec<Scalar> = Vec::new();

    for x_i in x {
        let y_i = p.eval(x_i).unwrap();
        y.push(y_i)
    }

    y
}


fn get_points_from_coordinates(x_vec: Vec<Scalar>, y_vec: Vec<Scalar>) -> Vec<(Scalar, Scalar)> {
    /* reshapes the format of coordinates into points
    */
    
    let mut points = Vec::<(Scalar, Scalar)>::new();

    for (x_i, y_i) in x_vec.iter().zip(y_vec.iter()) {
        let point: (Scalar, Scalar) = (x_i.clone(), y_i.clone());
        points.push(point)
    }

    points
}


fn make_random_shares(secret: Scalar, threshold: u32, n_shares: u32) -> Vec<(Scalar, Scalar)> {
    /* makes random shares
    */

    // check if threshold < n_shares

    let p = generate_random_polynomial(secret, threshold);

    let x_shares = generate_random_vector(n_shares);

    let y_shares = evaluate_polynomial(p, x_shares.clone());

    let shares = get_points_from_coordinates(x_shares, y_shares);

    shares
}


fn recover_secret(shares: Vec<(Scalar, Scalar)>, threshold: u32) -> Scalar {

    // check if n_shares >= threshold

    let recovered_secret = lagrange_interpolate(Scalar::zero(), &shares);

    recovered_secret
}

fn main() {

    /*  Example of Attribute Tree
     */ 
    let leaf_r = Node::new(5, Vec::new(), NodeType::AttributeNode(AttributeNodeType::Leaf(String::from("attr_s"))));
    let leaf_s = Node::new(6, Vec::new(), NodeType::AttributeNode(AttributeNodeType::Leaf(String::from("attr_s"))));

    let mut children_1: Vec<Node> = Vec::new(); children_1.push(leaf_r); children_1.push(leaf_s);
    let branch = Node::new(3, children_1, NodeType::AttributeNode(AttributeNodeType::Branch(1)));

    let leaf_q = Node::new(2, Vec::new(), NodeType::AttributeNode(AttributeNodeType::Leaf(String::from("attr_q"))));
    let leaf_p = Node::new(4, Vec::new(), NodeType::AttributeNode(AttributeNodeType::Leaf(String::from("attr_p"))));

    let mut children_2: Vec<Node> = Vec::new(); children_2.push(leaf_q); children_2.push(branch); children_2.push(leaf_p);
    let root = Node::new(1, children_2, NodeType::AttributeNode(AttributeNodeType::Branch(2)));

    //println!("{root:#?}");


    /*  At first, (1) Create an empty (zero) Secret tree (without any secret).
        Then, (2) the root of the secret tree contains a secret randomly 
        generated. All the other nodes of the secret tree are still empty (zero).
    */

    let mut csprng = OsRng;

    // Phase (1)
    let mut new_root = copy_tree(&root);

    //println!("{new_root:#?}");

    // Phase (2)
    let secret = Scalar::random(&mut csprng);

    println!("Recovered secret");
    println!("{:#?}", secret);

    new_root.set_node_type(NodeType::SecretNode(secret));

    //println!("Secret tree");
    //println!("{new_root:#?}");


    /*  Generate the other secret using SSS
    */
    
    let threshold = 3;
    let n_shares = 6;

    let shares = make_random_shares(secret, threshold, n_shares);

    //println!("x, y of the shares");
    //println!("{shares:#?}");

    let recov_secret = recover_secret(shares, threshold);

    println!("Recovered secret");
    println!("{:#?}", recov_secret);

    assert_eq!(secret, recov_secret)
}
