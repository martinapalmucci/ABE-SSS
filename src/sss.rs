use curve25519_dalek_ng::scalar::Scalar;
use rand_core::OsRng;
use thiserror::Error;

pub fn give_me_five() -> usize {
    5
}

#[derive(Error, Debug)]
pub enum SSSError {
    #[error("threshold must not be zero")]
    InvalidThreshold,
    #[error("must be threshold less then or equal to number of shares")]
    InvalidSchema,
}

fn schema_errors(threshold: usize, number_shares: usize) -> Option<SSSError> {
    if threshold < 1 {
        Some(SSSError::InvalidThreshold)
    } else if threshold > number_shares {
        Some(SSSError::InvalidSchema)
    } else {
        None
    }
}

/// Returns the shares of Shamir's Secret Sharing algorithm.
///
/// # Arguments
///
/// * `secret` - constant term of the polynomial
/// * `threshold` - degree of the polynomial
/// * `number_shares` - number of shares (or points) to be generated
///
#[must_use]
pub fn make_random_shares(
    secret: Scalar,
    threshold: usize,
    number_shares: usize,
) -> Result<Vec<(Scalar, Scalar)>, SSSError> {
    match schema_errors(threshold, number_shares) {
        None => {
            let mut csprng = OsRng;
            let mut polynomial = vec![secret];
            polynomial.extend(gen_random_vec(&mut csprng, threshold - 1));
            Ok(compute_random_points(
                &mut csprng,
                &polynomial,
                number_shares,
            ))
        }
        Some(e) => Err(e),
    }
}

/// Returns a scalar random vector.
fn gen_random_vec(csprng: &mut OsRng, length: usize) -> Vec<Scalar> {
    (0..length).map(|_| Scalar::random(csprng)).collect()
}

/// Returns a vector of (x, y) points based of a polynomial.
fn compute_random_points(
    csprng: &mut OsRng,
    polynomial: &[Scalar],
    n_points: usize,
) -> Vec<(Scalar, Scalar)> {
    let mut points = Vec::<(Scalar, Scalar)>::new();
    for _ in 0..n_points {
        let x = Scalar::random(csprng);
        let y = evaluate_polynomial(polynomial, x);
        points.push((x, y));
    }
    points
}

/// Returns the evaluation of a polynomial in the x-coordinate.
fn evaluate_polynomial(polynomial: &[Scalar], x: Scalar) -> Scalar {
    let mut y: Scalar = Scalar::zero();

    let mut curr_exp = Scalar::one();
    for a_i in polynomial {
        y += a_i * curr_exp;
        curr_exp *= x;
    }
    y
}

/// Returns the recovered secret.
///
/// # Arguments
///
/// * `shares` - points
/// * `threshold` - minimum number of shares to recover the secret
///
#[must_use]
pub fn recover_secret(shares: &[(Scalar, Scalar)], threshold: usize) -> Result<Scalar, SSSError> {
    match schema_errors(threshold, shares.len()) {
        None => Ok(lagrange_interpolate(Scalar::zero(), shares)),
        Some(e) => Err(e),
    }
}

/// Returns the result of the Lagrange interpolation.
fn lagrange_interpolate(x: Scalar, points: &[(Scalar, Scalar)]) -> Scalar {
    let mut y: Scalar = Scalar::default();

    for (j, (_, y_j)) in points.iter().enumerate() {
        let l_j = lagrange_polynomial(j, points, x);
        y += y_j * l_j;
    }

    y
}

/// Returns the result of the Lagrange polynomial
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
        let threshold = 3;
        let n_shares = 6; // try with multiple sets

        let mut csprng = OsRng;
        let secret = Scalar::random(&mut csprng);

        let shares = make_random_shares(secret, threshold, n_shares).unwrap();
        let recov_secret = recover_secret(&shares, threshold).unwrap();

        assert_eq!(secret, recov_secret);
    }
}
