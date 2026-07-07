//! `CPC.Prove` algorithm — non-interactive Sigma-protocol proof for one
//! step index.
//!
//! Implements the two-equation Lyubashevsky-style Sigma-protocol
//! `{ a * d_i = Delta_i, b * d_i = u_i }` with Fiat-Shamir-with-aborts,
//! producing a zero-knowledge, knowledge-sound, non-interactive proof.

use crate::commitment::Aux;
use crate::gauss::{log_rejection_m, rejection_acceptance_ratio, sample_gauss_poly};
use crate::merkle::MerklePath;
use crate::params::PublicParams;
use crate::ring::Poly;
use rand::Rng;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// A CPC proof `pi_i` for opening step index `i`.
///
/// Serialized size target: ~3.3 KB
/// (`z` ~0.8 KB + `u_i` ~0.8 KB + `t1` ~0.8 KB + `t2` ~0.8 KB + Merkle
/// path ~0.32 KB).
///
/// `t1, t2` are included in the proof (Option B) so that the verifier can
/// recompute the Fiat-Shamir challenge `c = H(com, deltas, i, t1, t2, mu)`
/// without needing a paper-transcript convention change.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone)]
pub struct Proof {
    /// Response polynomial `z = r + c * d_i` (after rejection sampling).
    pub z: Poly,
    /// Revealed leaf commitment `u_i = b * d_i`.
    pub u_i: Poly,
    /// Prover commitment `t1 = a * r` (Option B: included in proof).
    pub t1: Poly,
    /// Prover commitment `t2 = b * r` (Option B: included in proof).
    pub t2: Poly,
    /// Merkle authentication path for `u_i`.
    pub path: MerklePath,
}

/// Maximum rejection-sampling iterations before giving up.
///
/// Expected iterations are `~M_const ~= 2.7`; 1000 gives an astronomically low
/// failure probability for honest provers.
pub const MAX_REJECT_ITERATIONS: usize = 1000;

impl Proof {
    /// Compact binary serialization (no serde).
    ///
    /// Layout (little-endian):
    /// - `z`       : 768 bytes (3 * m)
    /// - `u_i`     : 768 bytes
    /// - `t1`      : 768 bytes
    /// - `t2`      : 768 bytes
    /// - `index`   : 8 bytes (u64)
    /// - `n_siblings` : 1 byte (must be <= 32)
    /// - `siblings` : 32 * n_siblings bytes
    ///
    /// Total: 3081 + 32*n_siblings bytes (~3.3 KB for L=1024, 10 siblings).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 * 768 + 8 + 1 + 32 * self.path.siblings.len());
        out.extend_from_slice(&self.z.to_bytes());
        out.extend_from_slice(&self.u_i.to_bytes());
        out.extend_from_slice(&self.t1.to_bytes());
        out.extend_from_slice(&self.t2.to_bytes());
        out.extend_from_slice(&(self.path.index as u64).to_le_bytes());
        assert!(self.path.siblings.len() <= 32, "Merkle path too deep");
        out.push(self.path.siblings.len() as u8);
        for sib in &self.path.siblings {
            out.extend_from_slice(sib);
        }
        out
    }

    /// Deserialize from [`Proof::to_bytes`] output.
    ///
    /// Returns `None` if the input is malformed.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        const POLY_BYTES: usize = 768;
        if b.len() < 4 * POLY_BYTES + 9 {
            return None;
        }
        let z = Poly::from_bytes(&b[0..POLY_BYTES])?;
        let u_i = Poly::from_bytes(&b[POLY_BYTES..2 * POLY_BYTES])?;
        let t1 = Poly::from_bytes(&b[2 * POLY_BYTES..3 * POLY_BYTES])?;
        let t2 = Poly::from_bytes(&b[3 * POLY_BYTES..4 * POLY_BYTES])?;
        let index = u64::from_le_bytes(b[4 * POLY_BYTES..4 * POLY_BYTES + 8].try_into().ok()?);
        let n_siblings = b[4 * POLY_BYTES + 8] as usize;
        if n_siblings > 32 {
            return None;
        }
        let siblings_start = 4 * POLY_BYTES + 9;
        let siblings_end = siblings_start + 32 * n_siblings;
        if b.len() != siblings_end {
            return None;
        }
        let mut siblings = Vec::with_capacity(n_siblings);
        for i in 0..n_siblings {
            let sib_start = siblings_start + 32 * i;
            let mut sib = [0u8; 32];
            sib.copy_from_slice(&b[sib_start..sib_start + 32]);
            siblings.push(sib);
        }
        Some(Proof {
            z,
            u_i,
            t1,
            t2,
            path: crate::merkle::MerklePath {
                index: index as usize,
                siblings,
            },
        })
    }
}

/// Run `CPC.Prove`.
///
/// `i` is the 1-based step index being opened (i.e., `d_i` lives at
/// `aux.d_vec[i - 1]`). `mu` is the verifier's context nonce (e.g., a
/// fresh random nonce).
///
/// Returns a [`Proof`] or panics if rejection sampling exceeds
/// [`MAX_REJECT_ITERATIONS`] (should not happen for honest inputs).
pub fn prove(pp: &PublicParams, aux: &Aux, i: usize, mu: &[u8]) -> Proof {
    prove_with_iteration_count(pp, aux, i, mu).0
}

/// Like [`prove`] but also returns the number of rejection-sampling
/// iterations consumed (1 = accepted on first try).
///
/// Useful for benchmarking and statistical analysis of the
/// Fiat-Shamir-with-aborts loop.
pub fn prove_with_iteration_count(
    pp: &PublicParams,
    aux: &Aux,
    i: usize,
    mu: &[u8],
) -> (Proof, usize) {
    assert!(
        i >= 1 && i <= aux.d_vec.len(),
        "prove: index i={} must be in 1..=L (L={})",
        i,
        aux.d_vec.len()
    );
    let d = &aux.d_vec[i - 1];
    let u_i = aux.u_vec[i - 1].clone();
    let com = aux.tree.root();

    // tau_ratio = sigma / T where T = beta * sqrt(m) (the secret norm bound).
    let t_bound = (pp.beta as f64) * (pp.m as f64).sqrt();
    let tau_ratio = pp.sigma / t_bound;
    let log_m = log_rejection_m(tau_ratio);

    let mut rng = rand::thread_rng();
    for iter in 0..MAX_REJECT_ITERATIONS {
        // 1. Sample masking polynomial r ~ D_sigma in R.
        let r = sample_gauss_poly(pp.sigma, &mut rng);

        // 2. Compute prover commitments t1 = a*r, t2 = b*r.
        let t1 = &pp.a * &r;
        let t2 = &pp.b_elem * &r;

        // 3. Fiat-Shamir challenge c = H(com, deltas, i, t1, t2, mu).
        let c = hash_to_challenge(&com, &aux.deltas, i, &t1, &t2, mu);

        // 4. Response z = r + c * d.
        let c_d = &c * d;
        let z = &r + &c_d;

        // 5. Rejection sampling: accept with probability
        //    rho = min(1, D_sigma(z) / (M_const * D_sigma(z - c*d))).
        //    Note z - c*d == r, which is the original masking polynomial.
        let z_minus_cd = &z - &c_d; // == r
        let rho = rejection_acceptance_ratio(&z, &z_minus_cd, pp.sigma, log_m);
        let u: f64 = rng.gen_range(0.0..1.0);
        if u <= rho {
            let path = aux.tree.generate_path(i - 1);
            return (
                Proof {
                    z,
                    u_i,
                    t1,
                    t2,
                    path,
                },
                iter + 1,
            );
        }
    }
    panic!(
        "prove: rejection sampling exceeded {} iterations (sigma={}, tau_ratio={:.4})",
        MAX_REJECT_ITERATIONS, pp.sigma, tau_ratio
    );
}

/// Hash-to-challenge: maps the transcript to a sparse `+-1` polynomial `c`
/// with exactly `tau` nonzero coefficients (Dilithium `SampleInBall`).
///
/// Transcript layout (concatenated, then SHAKE-256):
/// `com || serialize(Delta_1..Delta_L) || i || serialize(t1) || serialize(t2) || mu`
///
/// The output `c` has exactly `tau` nonzero coefficients, each in `{-1, +1}`
/// (stored as `1` and `q - 1` respectively in the non-centered representation).
pub fn hash_to_challenge(
    com: &crate::merkle::Hash,
    deltas: &[Poly],
    i: usize,
    t1: &Poly,
    t2: &Poly,
    mu: &[u8],
) -> Poly {
    use crate::params::{M, Q, TAU};

    let mut hasher = Shake256::default();
    hasher.update(com);
    for d in deltas {
        hasher.update(&d.to_bytes());
    }
    hasher.update(&(i as u64).to_le_bytes());
    hasher.update(&t1.to_bytes());
    hasher.update(&t2.to_bytes());
    hasher.update(mu);

    let mut out = Poly::zero();
    let mut xof = hasher.finalize_xof();

    // SampleInBall: pick `tau` distinct indices in [0, m), each with a random sign.
    let mut buf = [0u8; 1];
    let mut k = 0usize;
    while k < TAU {
        xof.read(&mut buf);
        let idx = (buf[0] as usize) % M;
        if out.coeffs[idx] == 0 {
            xof.read(&mut buf);
            out.coeffs[idx] = if buf[0] & 1 == 0 { 1 } else { Q - 1 };
            k += 1;
        }
    }
    out
}
