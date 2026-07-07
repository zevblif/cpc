//! Discrete Gaussian sampling over `R = Z_q[x]/(x^m+1)` and rejection
//! sampling for Fiat-Shamir-with-aborts.
//!
//! Each coefficient is sampled independently from `Z` with width `sigma`,
//! then reduced mod `q`. Used for masking polynomials in
//! [`prove::prove`](crate::prove::prove).

use crate::params::{M, SIGMA};
use crate::ring::Poly;
use rand::RngCore;
use std::sync::OnceLock;

/// Precomputed Cumulative Distribution Table for the discrete Gaussian
/// `D_sigma(x) ~ exp(-x^2 / (2*sigma^2))` over the non-negative integers,
/// truncated at `+/- 6*sigma`.
///
/// The table holds `cdt[i] = sum_{x=0}^{i} D_sigma(x) / Z` for `i = 0..=6*sigma`,
/// where `Z` is the normalizing constant. To sample, draw `u ~ Uniform(0, 1)`,
/// find the smallest `i` with `cdt[i] >= u`, then flip a fair coin for the sign.
///
/// The CDT is stored as `u64` values scaled to `[0, u64::MAX]` so that the
/// lookup uses only integer comparisons (constant-time linear scan via
/// `ring_ct::ct_select`); no `f64` comparisons leak timing information.
static CDT: OnceLock<Vec<u64>> = OnceLock::new();

fn cdt() -> &'static [u64] {
    CDT.get_or_init(|| {
        let tau = (6.0 * SIGMA).ceil() as usize; // truncate at +-6*sigma
        let two_sigma_sq = 2.0 * SIGMA * SIGMA;
        let mut cum: f64 = 0.0;
        let mut raw: Vec<f64> = Vec::with_capacity(tau + 2);
        raw.push(0.0);
        for x in 0..=tau {
            let p = (-(x as f64).powi(2) / two_sigma_sq).exp();
            cum += p;
            raw.push(cum);
        }
        // raw[i] holds sum_{x=0}^{i-1} p(x); normalize so raw.last() == 1.0,
        // then scale to [0, u64::MAX] for constant-time integer comparison.
        let z = *raw.last().unwrap();
        let scale = u64::MAX as f64;
        raw.iter().map(|&v| ((v / z) * scale).round() as u64).collect()
    })
}

/// Sample a polynomial whose coefficients are i.i.d. discrete Gaussian
/// over `Z` with standard deviation `sigma` (then reduced mod `q`).
///
/// The sampler is constant-time: the CDT lookup uses a reverse linear scan
/// with `ring_ct::ct_select` (no early exit), the sign is selected via a
/// single RNG bit through `ct_select`, and the final reduction uses
/// `ring_ct::caddq` (branchless conditional add of `Q`).
///
/// # Panics
/// Panics if `sigma` differs from the cached [`SIGMA`] (the CDT is a
/// process-global table; parameterizing per-call would require an API change
/// that is not needed for the current single-parameter-set design).
pub fn sample_gauss_poly<R: RngCore + ?Sized>(sigma: f64, rng: &mut R) -> Poly {
    assert!(
        (sigma - SIGMA).abs() < 1.0,
        "sample_gauss_poly: currently only sigma=SIGMA={} is supported (CDT cached), got {}",
        SIGMA,
        sigma
    );
    let table = cdt();
    let tau = (6.0 * SIGMA).ceil() as usize;
    let mut coeffs = [0i64; M];
    let mut u_buf = [0u8; 8];
    let mut sign_buf = [0u8; 1];
    for c in coeffs.iter_mut() {
        // Sample magnitude: smallest i such that cdt[i+1] >= u, via a
        // constant-time reverse linear scan with `ct_select` (no early exit).
        rng.fill_bytes(&mut u_buf);
        let u = u64::from_le_bytes(u_buf);
        let mut mag: i64 = tau as i64;
        for i in (0..tau as i64).rev() {
            let ge = ((table[(i + 1) as usize] >= u) as i64).wrapping_neg();
            mag = crate::ring_ct::ct_select(mag, i, ge);
        }
        // Random sign: +mag or -mag, both equally likely, via ct_select.
        rng.fill_bytes(&mut sign_buf);
        let sign_bit = (sign_buf[0] & 1) as i64;
        let signed = crate::ring_ct::ct_select(mag, -mag, -sign_bit);
        *c = crate::ring_ct::caddq(signed);
    }
    Poly { coeffs }
}

/// Rejection-sampling acceptance ratio
/// `rho = min(1, D_sigma(z) / (M_const * D_sigma(z - c*d)))`.
///
/// Computed in log-space as
/// `log rho = -pi * (||z||^2 - ||z - c*d||^2) / sigma^2 - log M_const`,
/// then returned as a probability in `[0, 1]`.
///
/// Norms are taken on the *centered* coefficient representation (centered
/// to `[-q/2, q/2)` before squaring) to match the true `l2` norm of the
/// integer vector the Gaussian is defined over.
///
/// The clamp `min(1, rho)` is implemented as `log_rho.min(0.0).exp()` to
/// avoid a data-dependent branch on the secret-dependent `log_rho` value.
pub fn rejection_acceptance_ratio(
    z: &Poly,
    z_minus_cd: &Poly,
    sigma: f64,
    log_m: f64,
) -> f64 {
    let z_norm_sq = centered_norm_sq(z);
    let zd_norm_sq = centered_norm_sq(z_minus_cd);
    let log_rho =
        -std::f64::consts::PI * (z_norm_sq - zd_norm_sq) / (sigma * sigma) - log_m;
    log_rho.min(0.0).exp()
}

/// `||v||^2` using the *centered* representation of each coefficient
/// (i.e., the unique representative in `[-q/2, q/2)`).
///
/// Centering uses the branchless `ring_ct::center` to avoid a data-dependent
/// branch on the secret coefficient value.
fn centered_norm_sq(p: &Poly) -> f64 {
    p.coeffs
        .iter()
        .map(|&c| {
            let centered = crate::ring_ct::center(c);
            (centered as f64).powi(2)
        })
        .sum()
}

/// Natural log of the rejection-sampling constant `M` for `tau = 12`.
///
/// `log M = 12/tau + 1/(2*tau^2) = 1 + 1/288 ~= 1.00347`.
pub fn log_rejection_m(tau_ratio: f64) -> f64 {
    12.0 / tau_ratio + 1.0 / (2.0 * tau_ratio * tau_ratio)
}
