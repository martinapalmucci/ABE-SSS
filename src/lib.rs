pub mod chachapoly;
pub mod ecies;
pub mod lagrange;
pub mod sss;
pub mod trees;
pub mod utils;

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
