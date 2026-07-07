//! `CPC.Verify` algorithm.
//!
//! Recomputes the verifier-side transcript, checks the response norm bound,
//! verifies the Fiat-Shamir challenge hash, and checks the Merkle
//! authentication path.

use crate::merkle::{verify_path, Hash};
use crate::params::PublicParams;
use crate::prove::{hash_to_challenge, Proof};
use crate::ring::Poly;

/// Run `CPC.Verify` (Option B: `t1, t2` are carried in the proof).
///
/// `deltas` is the full sequence `{Delta_j = a * d_j}_{j=1..L}` published at
/// commit time. `i` is the 1-based step index being opened. `mu` is the
/// verifier's context nonce (must match the one used in `Prove`).
///
/// Returns `true` iff all of the following hold:
/// 1. `||z||_2 <= B` (response norm bound)
/// 2. `c` recomputed from `H(com, deltas, i, t1, t2, mu)` satisfies
///    `a * z == t1 + c * Delta_i` and `b * z == t2 + c * u_i`
/// 3. The Merkle path for `u_i` is valid under `com`
pub fn verify(
    pp: &PublicParams,
    com: &Hash,
    deltas: &[Poly],
    i: usize,
    proof: &Proof,
    mu: &[u8],
) -> bool {
    // 1. Response norm bound.
    if proof.z.norm_l2() > pp.b as f64 {
        return false;
    }

    // 2. Index bounds.
    if i < 1 || i > deltas.len() {
        return false;
    }
    let delta_i = &deltas[i - 1];
    let u_i = &proof.u_i;

    // 3. Recompute the Fiat-Shamir challenge from the (t1, t2) carried in the proof.
    let c = hash_to_challenge(com, deltas, i, &proof.t1, &proof.t2, mu);

    // 4. Check the two Sigma-protocol equations:
    //      a * z == t1 + c * Delta_i
    //      b * z == t2 + c * u_i
    let az = &pp.a * &proof.z;
    let bz = &pp.b_elem * &proof.z;
    let c_delta = &c * delta_i;
    let c_u = &c * u_i;
    let lhs1 = &proof.t1 + &c_delta;
    let lhs2 = &proof.t2 + &c_u;
    if az.coeffs != lhs1.coeffs {
        return false;
    }
    if bz.coeffs != lhs2.coeffs {
        return false;
    }

    // 5. Merkle authentication path for u_i under com.
    verify_path(com, &u_i.to_bytes(), &proof.path)
}
