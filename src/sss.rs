use curve25519_dalek_ng::scalar::Scalar;
use rand_core::OsRng;
use thiserror::Error;

use crate::{concat_arrays, lagrange::lagrange_interpolate};

#[derive(Debug, Clone)]
pub struct Share {
    x: Scalar,
    y: Scalar,
}

impl Share {
    pub fn new(x: Scalar, y: Scalar) -> Share {
        Share { x, y }
    }

    pub fn random(p: &Polynomial) -> Share {
        let x = Scalar::random(&mut OsRng);
        let y = p.evaluate(x);
        Share::new(x, y)
    }

    pub fn parse_point(point: &(Scalar, Scalar)) -> Share {
        Share {
            x: point.0,
            y: point.1,
        }
    }

    pub fn parse_msg(msg: &[u8]) -> Share {
        let (x, y) = msg.split_at(32);
        let x = Scalar::from_bits(<[u8; 32]>::try_from(x).unwrap());
        let y = Scalar::from_bits(<[u8; 32]>::try_from(y).unwrap());

        Share { x, y }
    }

    pub fn serialize(&self) -> (Scalar, Scalar) {
        (self.x, self.y)
    }

    pub fn serialize_chain(&self) -> Vec<u8> {
        let (x, y) = self.serialize();
        concat_arrays(x.to_bytes(), y.to_bytes())
    }
}

#[derive(Debug, Clone)]
pub struct Polynomial {
    coefficients: Vec<Scalar>, // from constant term to greater grade term
}

impl Polynomial {
    pub fn random(degree: usize) -> Polynomial {
        let coeffs = (0..degree).map(|_| Scalar::random(&mut OsRng)).collect();
        Polynomial {
            coefficients: coeffs,
        }
    }

    pub fn from_constant_term(constant_term: Scalar, degree: usize) -> Polynomial {
        let mut coeffs = Vec::with_capacity(degree);
        coeffs.push(constant_term);

        let a_i: Vec<Scalar> = (0..(degree - 1))
            .map(|_| Scalar::random(&mut OsRng))
            .collect();
        coeffs.extend(a_i);

        Polynomial {
            coefficients: coeffs,
        }
    }

    fn evaluate(&self, x: Scalar) -> Scalar {
        let mut y: Scalar = Scalar::zero();

        let mut curr_exp = Scalar::one();
        for a_i in &self.coefficients {
            y += a_i * curr_exp;
            curr_exp *= x;
        }
        y
    }
}

#[derive(Error, Debug)]
pub enum SSSError {
    #[error("threshold must not be zero")]
    InvalidThreshold,
    #[error("must be threshold less then or equal to number of shares")]
    InvalidSchema,
}

#[derive(Debug, Clone)]
pub struct SSS {
    threshold: usize,
    number_shares: usize,
}

impl SSS {
    /// Returns the (t, n) - Shamir's Secret Sharing schema.
    ///
    /// # Arguments
    ///
    /// * `threshold` - Threshold in SSS algorithm
    /// * `number_shares` - Number of shares in SSS algorithm
    pub fn new(threshold: usize, number_shares: usize) -> Result<Self, SSSError> {
        if threshold < 1 {
            Err(SSSError::InvalidThreshold)
        } else if threshold > number_shares {
            Err(SSSError::InvalidSchema)
        } else {
            let schema = Self {
                threshold,
                number_shares,
            };
            Ok(schema)
        }
    }

    /// Returns the shares of Shamir's Secret Sharing algorithm.
    ///
    /// # Arguments
    ///
    /// * `secret` - A Scalar reference to the constant term of a polynomial
    #[must_use]
    pub fn make_random_shares(&self, secret: Scalar) -> Vec<Share> {
        let p = Polynomial::from_constant_term(secret, self.threshold);

        let mut shares: Vec<Share> = Vec::with_capacity(self.number_shares);
        for _ in 0..self.number_shares {
            let share = Share::random(&p);
            shares.push(share)
        }
        shares
    }

    /// Returns the recovered secret.
    ///
    /// # Arguments
    ///
    /// * `shares` - points
    #[must_use]
    pub fn recover_secret(&self, shares: &[Share]) -> Scalar {
        let points = shares
            .iter()
            .map(|share| share.serialize())
            .collect::<Vec<(Scalar, Scalar)>>();
        lagrange_interpolate(Scalar::zero(), &points)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek_ng::scalar::Scalar;
    use rand_core::OsRng;

    #[test]
    fn sss_test() {
        let threshold = 3;
        let n_shares = 6; // try with multiple sets

        let secret = Scalar::random(&mut OsRng);

        let schema = SSS::new(threshold, n_shares);
        let schema = schema.unwrap();

        let shares = schema.make_random_shares(secret);
        let recov_secret = schema.recover_secret(&shares);

        assert_eq!(secret, recov_secret);
    }
}
