use curve25519_dalek_ng::scalar::Scalar;
use rand_core::OsRng;

// algorithm
fn compute_interpolation_lagrange(x: Scalar, points: &[(Scalar, Scalar)]) -> Scalar {

    let mut L_x: Scalar = Scalar::zero();

    for (j, (_, y_j)) in points.iter().enumerate() {
        let l_j = compute_lagrange_polinomial(j, points, x);
        L_x += y_j * l_j;
    }

    L_x
}

fn compute_lagrange_polinomial(j: usize, points: &[(Scalar, Scalar)], x: Scalar) -> Scalar {
    
    let mut l_j: Scalar = Scalar::one();

    let x_j = points[j].0;

    for (m, (x_m, _)) in points.iter().enumerate() {
        if m != j {
            l_j *= (x - x_m) * (x_j - x_m).invert();
        }
    }

    l_j
}


fn main() {
    
    let mut csprng = OsRng;

    let x = Scalar::zero();
    let mut points = Vec::<(Scalar, Scalar)>::new();
    for _ in 0..10 {
        points.push((Scalar::random(&mut csprng), Scalar::random(&mut csprng)));
    }
    let index_j = 2;

    let lagrange_pol = compute_interpolation_lagrange(x, &points);

    println!("{:?}", lagrange_pol);
}