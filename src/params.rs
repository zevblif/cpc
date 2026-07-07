//! CPC parameter set.
//!
//! All values follow the paper's Section 7 (Parameter Selection).
//! Security target: 128-bit (Ring-SIS core-SVP cost).

/// Ring dimension `m = 256`.
pub const M: usize = 256;

/// Modulus `q = 8380417` (NTT-friendly prime, `q = 1 mod 512`).
pub const Q: i64 = 8_380_417;

/// Challenge polynomial weight `tau = 60`.
pub const TAU: usize = 60;

/// Step `l2` bound `beta = 45`.
pub const BETA: i64 = 45;

/// Gaussian parameter `sigma = 12 * tau * beta = 32400`.
pub const SIGMA: f64 = 32_400.0;

/// Response truncation bound `B = 1.2 * sigma * sqrt(m) ~= 622080`.
pub const B: i64 = 622_080;

/// Example maximum path length `L = 1024`.
pub const MAX_PATH_LEN: usize = 1024;

/// Knowledge-soundness extraction norm bound `4 * tau * m * B ~= 2.4e9`.
pub const EXTRACT_NORM_BOUND: i64 = 4 * (TAU as i64) * (M as i64) * B;

/// Public parameters produced by `Setup`.
///
/// Carries the scalar parameters together with the public ring elements
/// `a, b` (sampled uniformly in `R = Z_q[x]/(x^m+1)`) so future parameter
/// sets (e.g., a higher-security variant with `m = 512`) can be swapped
/// without changing call sites.
#[derive(Clone, Debug)]
pub struct PublicParams {
    /// Ring dimension.
    pub m: usize,
    /// Modulus.
    pub q: i64,
    /// Challenge weight.
    pub tau: usize,
    /// Step `l2` bound.
    pub beta: i64,
    /// Gaussian width.
    pub sigma: f64,
    /// Response `l2` bound.
    pub b: i64,
    /// Maximum supported path length.
    pub max_path_len: usize,
    /// Public projection ring element `a` (uniform in `R`).
    pub a: crate::ring::Poly,
    /// Hiding commitment ring element `b` (uniform in `R`).
    pub b_elem: crate::ring::Poly,
}

impl PublicParams {
    /// Build the default parameter set, sampling `a, b` deterministically
    /// from `seed` via SHAKE-256 expansion in `R`.
    ///
    /// Each coefficient is sampled by reading 3 bytes from a SHAKE-256
    /// stream and rejecting values `>= q` (so the result is uniform in
    /// `[0, q)`). Different domain-separation prefixes ensure `a` and `b`
    /// are independent.
    pub fn setup(seed: &[u8]) -> Self {
        let a = sample_poly_uniform(seed, b"cpc-public-params-a/");
        let b_elem = sample_poly_uniform(seed, b"cpc-public-params-b/");

        Self {
            m: M,
            q: Q,
            tau: TAU,
            beta: BETA,
            sigma: SIGMA,
            b: B,
            max_path_len: MAX_PATH_LEN,
            a,
            b_elem,
        }
    }
}

/// Sample a uniformly random polynomial in `R` from `seed` using SHAKE-256,
/// with domain separator `prefix`. Uses rejection sampling on 3-byte values
/// to ensure uniformity in `[0, q)`.
fn sample_poly_uniform(seed: &[u8], prefix: &[u8]) -> crate::ring::Poly {
    use sha3::{Shake256, digest::{ExtendableOutput, Update, XofReader}};
    use crate::params::{M, Q};
    use crate::ring::Poly;

    let mut hasher = Shake256::default();
    hasher.update(prefix);
    hasher.update(seed);
    let mut xof = hasher.finalize_xof();

    let mut coeffs = [0i64; M];
    let mut buf = [0u8; 3];
    let mut filled = 0usize;
    while filled < M {
        // Pull 3 bytes; interpret as little-endian 24-bit integer in [0, 2^24).
        // Since q = 8380417 < 2^24 = 16777216, rejection gives uniformity.
        xof.read(&mut buf);
        let val = (buf[0] as u64) | ((buf[1] as u64) << 8) | ((buf[2] as u64) << 16);
        if val < Q as u64 {
            coeffs[filled] = val as i64;
            filled += 1;
        }
    }
    Poly { coeffs }
}
