use rand_core::OsRng;
use curve25519_dalek_ng::scalar::Scalar;

// SSS algorithm

// Making random shares
#[must_use]
pub fn make_random_shares(secret: Scalar, threshold: usize, n_shares: usize) -> Vec<(Scalar, Scalar)> {
    /* makes random shares
     */

    // check if threshold < n_shares

    let mut p = vec![secret];
    p.extend(generate_random_vector(threshold - 1));

    let x_coordinate = generate_random_vector(n_shares);
    get_shares(&x_coordinate, &p)
}

fn generate_random_vector(length: usize) -> Vec<Scalar> {
    /*  generates a random vector with
        "length" number of elements
    */
    let mut csprng = OsRng;

    let mut vec: Vec<Scalar> = Vec::new();
    for _ in 0..length {
        let v_i = Scalar::random(&mut csprng);
        vec.push(v_i);
    }
    vec
}

fn get_shares(x_vec: &[Scalar], polynomial: &[Scalar]) -> Vec<(Scalar, Scalar)> {
    /* reshapes the format of coordinates into points
     */
    let mut shares = Vec::<(Scalar, Scalar)>::new();

    for x_i in x_vec {
        let y_i = evaluate_polynomial(polynomial, *x_i);
        let share: (Scalar, Scalar) = (*x_i, y_i);
        shares.push(share);
    }
    shares
}

fn evaluate_polynomial(polynomial: &[Scalar], x: Scalar) -> Scalar {
    /*  returns the y-coordinates evaluated on a
        polinomial "p" in the x-coordinates "x"
    */
    let mut y: Scalar = Scalar::zero();

    let mut curr_exp = Scalar::one();
    for a_i in polynomial {
        y += a_i * curr_exp;
        curr_exp *= x;
    }
    y
}

// Recovering secret
#[must_use]
pub fn recover_secret(shares: &[(Scalar, Scalar)], threshold: usize) -> Scalar {
    
    // check if n_shares >= threshold

    lagrange_interpolate(Scalar::zero(), shares)
}

// Lagrange interpolation
fn lagrange_interpolate(x: Scalar, points: &[(Scalar, Scalar)]) -> Scalar {
    let mut y: Scalar = Scalar::zero();

    for (j, (_, y_j)) in points.iter().enumerate() {
        let l_j = lagrange_polynomial(j, points, x);
        y += y_j * l_j;
    }

    y
}

fn lagrange_polynomial(j: usize, points: &[(Scalar, Scalar)], x: Scalar) -> Scalar {
    let mut l_j: Scalar = Scalar::one();

    let x_j = points[j].0;

    for (m, (x_m, _)) in points.iter().enumerate() {
        if m != j {
            l_j *= (x - x_m) * (x_j - x_m).invert();
        }
    }
    l_j
}


#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek_ng::scalar::Scalar;
    use rand_core::OsRng;

    #[test]
    fn lagrange_interpolation_test() {
        let mut csprng = OsRng;

        let rnd = Scalar::random(&mut csprng);

        let point0: (Scalar, Scalar) = (Scalar::zero(), Scalar::zero());
        let point1: (Scalar, Scalar) = (Scalar::one(), rnd);
        let two = Scalar::one() + Scalar::one();
        let point2: (Scalar, Scalar) = (two, two * rnd);

        let mut points = Vec::<(Scalar, Scalar)>::new();
        points.push(point0);
        points.push(point1);
        points.push(point2);

        let ret = lagrange_interpolate(Scalar::one(), &points);

        assert_eq!(ret, rnd);
    }

    #[test]
    fn sss_test() {
        let threshold = 3; let n_shares = 6; // try with multiple sets

        let mut csprng = OsRng;
        let secret = Scalar::random(&mut csprng);

        let shares = make_random_shares(secret, threshold, n_shares);
        let recov_secret = recover_secret(&shares, threshold);

        assert_eq!(secret, recov_secret);
    }
}
