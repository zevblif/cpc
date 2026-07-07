//! CPC: Constrained Path Commitment.
//!
//! A post-quantum primitive for selectively disclosing structured paths with
//! zero-knowledge shortness proofs. See [`paper.md`](../paper.md) for the full
//! construction and [`formal-proof.md`](../formal-proof.md) for security proofs.
//!
//! # Module layout
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`params`]      | Parameter constants and `PublicParams` |
//! | [`ring`]        | Polynomial ring `R = Z_q[x]/(x^m+1)` arithmetic + NTT |
//! | [`gauss`]       | Discrete Gaussian sampling and rejection sampling |
//! | [`merkle`]      | SHA3-256 Merkle tree for sequence binding |
//! | [`commitment`]  | `CPC.Commit` algorithm |
//! | [`prove`]       | `CPC.Prove` non-interactive Sigma-protocol |
//! | [`verify`]      | `CPC.Verify` algorithm |

pub mod commitment;
pub mod gauss;
pub mod merkle;
pub mod params;
pub mod prove;
pub mod ring;
pub mod ring_ct;
pub mod verify;

pub use commitment::{commit, Aux};
pub use params::PublicParams;
pub use prove::{prove, Proof};
pub use verify::verify;
