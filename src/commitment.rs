//! `CPC.Commit` algorithm.
//!
//! Computes per-step SIS hiding commitments `u_i = b * d_i`, builds a Merkle
//! tree over them, and returns the tree root as the public commitment.
//! Also exposes the public projections `Delta_i = a * d_i` that the verifier
//! needs to challenge the prover.

use crate::merkle::{Hash, MerkleTree};
use crate::params::PublicParams;
use crate::ring::Poly;

/// Auxiliary information retained by the committer.
///
/// All secret state lives here: the differences `d_i`, the hiding
/// commitments `u_i`, the public projections `Delta_i`, and the Merkle
/// tree (needed to generate authentication paths during `Prove`).
pub struct Aux {
    /// Step differences `d_i = v_i - v_{i-1}` for `i = 1..=L`.
    pub d_vec: Vec<Poly>,
    /// Hiding commitments `u_i = b * d_i` (Merkle leaves).
    pub u_vec: Vec<Poly>,
    /// Public projections `Delta_i = a * d_i` (verifier-side input).
    pub deltas: Vec<Poly>,
    /// The Merkle tree (for path generation during `Prove`).
    pub tree: MerkleTree,
}

/// Run `CPC.Commit`.
///
/// `path` is the sequence `v_0, v_1, ..., v_L` (length `L + 1`). Each step
/// difference `d_i = v_i - v_{i-1}` must satisfy `||d_i||_2 <= beta`; a
/// violation causes a panic with a descriptive message.
///
/// Returns `(com, aux)` where `com` is the 32-byte Merkle root and `aux`
/// is the secret state used by [`prove`](crate::prove::prove).
pub fn commit(pp: &PublicParams, path: &[Poly]) -> (Hash, Aux) {
    assert!(
        path.len() >= 2,
        "commit: path must contain at least v_0 and v_1 (got length {})",
        path.len()
    );
    let l = path.len() - 1;

    let mut d_vec = Vec::with_capacity(l);
    let mut u_vec = Vec::with_capacity(l);
    let mut deltas = Vec::with_capacity(l);
    let mut leaves: Vec<Vec<u8>> = Vec::with_capacity(l);

    for i in 0..l {
        // d_i = v_{i+1} - v_i  (in R_q)
        let d = &path[i + 1] - &path[i];
        let norm = d.norm_l2();
        assert!(
            norm <= pp.beta as f64,
            "commit: step {} difference ||d_i||_2 = {} exceeds beta = {}",
            i + 1,
            norm,
            pp.beta
        );

        // u_i = b * d_i  (Merkle leaf; SIS hiding commitment)
        let u = &pp.b_elem * &d;
        // Delta_i = a * d_i  (public projection)
        let delta = &pp.a * &d;

        leaves.push(u.to_bytes());
        d_vec.push(d);
        u_vec.push(u);
        deltas.push(delta);
    }

    let tree = MerkleTree::build(&leaves);
    let com = tree.root();
    (com, Aux { d_vec, u_vec, deltas, tree })
}
