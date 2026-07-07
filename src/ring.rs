//! Polynomial ring `R = Z_q[x] / (x^m + 1)` arithmetic.
//!
//! `m = 256`, `q = 8380417` (NTT-friendly prime, `q = 1 mod 2m`).
//! Multiplication uses the Number-Theoretic Transform.

use crate::params::{M, Q};
use crate::ring_ct::{barrett_reduce, caddq, csubq, center};
use std::sync::OnceLock;

/// A polynomial in `R`, stored as `m = 256` coefficients in `[0, q)`.
///
/// Coefficients are kept in the *non-centered* representation `[0, q)`;
/// callers that need norms must center them to `[-q/2, q/2)` first.
///
/// `Serialize`/`Deserialize` are implemented manually under the `serde`
/// feature (rather than derived) because `[i64; 256]` exceeds serde's
/// 32-element derive limit. The manual impl reuses [`Poly::to_bytes`] /
/// [`Poly::from_bytes`] so the wire format is the compact 768-byte form.
#[derive(Clone, Debug)]
pub struct Poly {
    /// Coefficients, lowest-degree first.
    pub coeffs: [i64; M],
}

/// 8-bit reversal of `k` (used for the NTT twiddle-factor table).
fn brv8(mut k: usize) -> usize {
    let mut r = 0usize;
    for _ in 0..8 {
        r = (r << 1) | (k & 1);
        k >>= 1;
    }
    r
}

/// Modular exponentiation `base^e mod m` (Fermat-style, m must be prime).
fn mod_pow(mut base: i64, mut e: u64, m: i64) -> i64 {
    let mut result = 1i64;
    base = ((base % m) + m) % m;
    while e > 0 {
        if e & 1 == 1 {
            result = (result * base) % m;
        }
        base = (base * base) % m;
        e >>= 1;
    }
    result
}

/// Precomputed twiddle factors `zetas[k] = ζ^{brv8(k)} mod q` for `k = 0..M`,
/// where `ζ = 1753` is a primitive `2m`-th root of unity mod `q` (so `ζ^m = -1`).
static ZETAS: OnceLock<Vec<i64>> = OnceLock::new();

fn zetas() -> &'static [i64] {
    ZETAS.get_or_init(|| {
        const ZETA_ROOT: i64 = 1753;
        let mut table = vec![0i64; M];
        for k in 0..M {
            table[k] = mod_pow(ZETA_ROOT, brv8(k) as u64, Q);
        }
        table
    })
}

impl Poly {
    /// The zero polynomial.
    pub fn zero() -> Self {
        Self { coeffs: [0; M] }
    }

    /// Build from a slice of `i32` coefficients (length must be `<= M`;
    /// missing high-degree coefficients default to 0).
    ///
    /// Negative values are reduced into `[0, q)`.
    pub fn from_coefficients(c: &[i32]) -> Self {
        assert!(c.len() <= M, "coefficient slice length {} exceeds M={}", c.len(), M);
        let mut coeffs = [0i64; M];
        for (i, &v) in c.iter().enumerate() {
            coeffs[i] = (v as i64).rem_euclid(Q);
        }
        Self { coeffs }
    }

    /// Negation (additive inverse in `R`).
    pub fn neg(&self) -> Self {
        let mut out = self.clone();
        for c in out.coeffs.iter_mut() {
            *c = (Q - *c) % Q;
        }
        out
    }

    /// `l2` norm of the *centered* coefficient vector.
    pub fn norm_l2(&self) -> f64 {
        let s: f64 = self.coeffs.iter().map(|&c| {
            let c = center(c).abs();
            (c as f64).powi(2)
        }).sum();
        s.sqrt()
    }

    /// `l_inf` norm of the *centered* coefficient vector.
    pub fn norm_inf(&self) -> i64 {
        self.coeffs.iter().map(|&c| center(c).abs()).max().unwrap_or(0)
    }

    /// In-place forward NTT (Cooley-Tukey, negacyclic, bit-reversed output).
    ///
    /// Follows FIPS 204 Algorithm 41: `k` runs `1, 2, ..., M-1`; `len` runs
    /// `M/2, M/4, ..., 1`; twiddle factor at step `k` is `ζ^{brv8(k)}`.
    ///
    /// Constant-time: twiddle multiply uses [`barrett_reduce`], butterfly
    /// uses [`csubq`]/[`caddq`] (no `% Q` / `rem_euclid`).
    pub fn ntt(&mut self) {
        let z = zetas();
        let mut k = 0usize;
        let mut len = M / 2; // 128
        while len > 0 {
            let mut start = 0usize;
            while start < M {
                k += 1;
                let zeta = z[k];
                for j in start..start + len {
                    let t = barrett_reduce(zeta * self.coeffs[j + len]);
                    self.coeffs[j + len] = caddq(self.coeffs[j] - t);
                    self.coeffs[j] = csubq(self.coeffs[j] + t);
                }
                start += 2 * len;
            }
            len >>= 1;
        }
    }

    /// In-place inverse NTT (Gentleman-Sande), with final scaling by `m^{-1} mod q`.
    ///
    /// Follows FIPS 204 Algorithm 42: `k` runs `M-1, M-2, ..., 1`; `len` runs
    /// `1, 2, ..., M/2`; twiddle factor at step `k` is `-ζ^{brv8(k)} mod q`.
    ///
    /// Constant-time: twiddle multiply uses [`barrett_reduce`], butterfly
    /// uses [`csubq`]/[`caddq`] (no `% Q` / `rem_euclid`).
    pub fn inv_ntt(&mut self) {
        let z = zetas();
        let mut k = M; // 256
        let mut len = 1usize;
        while len < M {
            let mut start = 0usize;
            while start < M {
                k -= 1;
                let zeta = csubq(Q - z[k]); // -zetas[k] mod q, CT
                for j in start..start + len {
                    let t = self.coeffs[j];
                    self.coeffs[j] = csubq(t + self.coeffs[j + len]);
                    let diff = caddq(t - self.coeffs[j + len]);
                    self.coeffs[j + len] = barrett_reduce(zeta * diff);
                }
                start += 2 * len;
            }
            len <<= 1;
        }
        // scale by m^{-1} mod q (Fermat: m^{-1} = m^{q-2} mod q)
        let m_inv = mod_pow(M as i64, (Q - 2) as u64, Q);
        for c in self.coeffs.iter_mut() {
            *c = barrett_reduce(*c * m_inv);
        }
    }

    /// Pointwise multiplication in NTT domain. Both inputs must already be
    /// in NTT form; the result is also in NTT form.
    ///
    /// Constant-time: uses [`barrett_reduce`] (no `% Q`).
    pub fn pointwise_mul(&self, other: &Self) -> Self {
        let mut out = Poly::zero();
        for i in 0..M {
            out.coeffs[i] = barrett_reduce(self.coeffs[i] * other.coeffs[i]);
        }
        out
    }

    /// Serialize to bytes: 3 bytes per coefficient, little-endian.
    ///
    /// Total length: `3 * M = 768` bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 * M);
        for &c in &self.coeffs {
            let c = c as u64;
            out.push((c & 0xFF) as u8);
            out.push(((c >> 8) & 0xFF) as u8);
            out.push(((c >> 16) & 0xFF) as u8);
        }
        out
    }

    /// Deserialize from [`Poly::to_bytes`] output.
    ///
    /// Returns `None` if the input is malformed or any coefficient is `>= q`.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != 3 * M {
            return None;
        }
        let mut coeffs = [0i64; M];
        for i in 0..M {
            let c = (b[3 * i] as u64) | ((b[3 * i + 1] as u64) << 8) | ((b[3 * i + 2] as u64) << 16);
            if c >= Q as u64 {
                return None;
            }
            coeffs[i] = c as i64;
        }
        Some(Self { coeffs })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Poly {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Poly {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PolyVisitor;

        impl<'de> serde::de::Visitor<'de> for PolyVisitor {
            type Value = Poly;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a byte buffer of length {}", 3 * M)
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Poly, E> {
                Poly::from_bytes(v).ok_or_else(|| E::custom(format!("malformed Poly bytes (len={})", v.len())))
            }

            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Poly, E> {
                self.visit_bytes(&v)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Poly, A::Error> {
                use serde::de::Error;
                let mut buf = Vec::with_capacity(3 * M);
                while let Some(b) = seq.next_element::<u8>()? {
                    buf.push(b);
                }
                Poly::from_bytes(&buf).ok_or_else(|| A::Error::custom(format!("malformed Poly bytes (len={})", buf.len())))
            }
        }

        deserializer.deserialize_bytes(PolyVisitor)
    }
}

impl std::ops::Add<&Poly> for &Poly {
    type Output = Poly;
    fn add(self, rhs: &Poly) -> Poly {
        let mut out = Poly::zero();
        for i in 0..M {
            out.coeffs[i] = csubq(self.coeffs[i] + rhs.coeffs[i]);
        }
        out
    }
}

impl std::ops::Sub<&Poly> for &Poly {
    type Output = Poly;
    fn sub(self, rhs: &Poly) -> Poly {
        let mut out = Poly::zero();
        for i in 0..M {
            out.coeffs[i] = caddq(self.coeffs[i] - rhs.coeffs[i]);
        }
        out
    }
}

impl std::ops::Mul<&Poly> for &Poly {
    type Output = Poly;
    fn mul(self, rhs: &Poly) -> Poly {
        let mut a = self.clone();
        let mut b = rhs.clone();
        a.ntt();
        b.ntt();
        let mut c = a.pointwise_mul(&b);
        c.inv_ntt();
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntt_round_trip() {
        let mut p = Poly::from_coefficients(&[1, 2, 3, 4, 5, 6, 7, 8, -1, -2, -3, -4, 0, 0, 0, 0]);
        let original = p.clone();
        p.ntt();
        p.inv_ntt();
        assert_eq!(p.coeffs, original.coeffs, "inv_ntt(ntt(p)) must equal p");
    }

    #[test]
    fn mul_matches_schoolbook() {
        // a = 1 + 2x, b = 3 + 4x  ->  a*b = 3 + 10x + 8x^2  (no wrap for deg < m)
        let a = Poly::from_coefficients(&[1, 2]);
        let b = Poly::from_coefficients(&[3, 4]);
        let got = &a * &b;

        let mut want = [0i64; M];
        for i in 0..M {
            for j in 0..M {
                let k = i + j;
                let v = a.coeffs[i] * b.coeffs[j];
                if k < M {
                    want[k] = (want[k] + v) % Q;
                } else {
                    want[k - M] = (want[k - M] - v).rem_euclid(Q);
                }
            }
        }
        assert_eq!(got.coeffs, want);
    }
}
