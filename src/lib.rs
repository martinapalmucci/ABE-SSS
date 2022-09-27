pub mod chachapoly;
pub mod ecies;
pub mod sss;
pub mod utils;

use thiserror::Error;

use curve25519_dalek_ng::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand_core::OsRng;
use utils::generate_keypair;

pub fn chain_point(point: &(Scalar, Scalar)) -> Vec<u8> {
    let fst = point.0.to_bytes();
    let snd = point.1.to_bytes();
    concat_arrays(fst, snd)
}

fn concat_arrays<const N: usize, const M: usize>(fst: [u8; N], snd: [u8; M]) -> Vec<u8> {
    let mut result = Vec::new();
    for n in 0..(N + M) {
        let cond = n < N;
        let i = if cond { n } else { n - N };
        let value = (cond as u8) * fst[i] + (!cond as u8) * snd[i];
        result.push(value)
    }
    result
}
