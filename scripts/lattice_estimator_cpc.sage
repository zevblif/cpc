#!/usr/bin/env sage
# -*- coding: utf-8 -*-
"""
Core-SVP cost estimation for CPC's Ring-SIS instance.

CPC reuses the Dilithium-III ring (m=256, q=8380417). Two distinct norm
bounds arise in the security proofs:

1. Binding SIS bound (Theorem 1):  nu_bind = 2B + 2*tau*beta*sqrt(m)
                                      ~= 1.33e6  < q  (security-critical)
   This is the SIS hardness parameter underlying binding. Since
   nu_bind < q, the SIS instance is non-trivial and its Core-SVP cost
   should match Dilithium-III (~128 bit classical / ~118 bit quantum).

2. Extraction bound (Theorem 3):    nu_ext  = 4*tau*sqrt(m)*B
                                      ~= 2.39e9  > q
   This bounds the extracted witness norm in knowledge soundness. Since
   nu_ext > q, standard SIS with beta = nu_ext admits trivial solutions
   (e.g. x = (q,0,...,0)). The lattice-estimator will invoke the
   [DucEspPos23] large-norm attack for this regime. NOTE: knowledge
   soundness does NOT rely on SIS hardness at nu_ext; it is a knowledge
   statement (the extractor produces d* with a*d* = Delta_i, b*d* = u,
   not a SIS solution).

Run (Linux/WSL2 with SageMath + lattice-estimator installed):
    sage scripts/lattice_estimator_cpc.sage
"""

import json
import sys
import math

try:
    from estimator import SIS
    from sage.all import oo
except ImportError as e:
    print("ERROR: lattice-estimator or SageMath not available.")
    print("Install (Linux/WSL2):")
    print("  sudo apt install sagemath")
    print("  git clone https://github.com/malb/lattice-estimator.git")
    print("  cd lattice-estimator && sage -pip install -e .")
    print("Detail: %s" % e)
    sys.exit(1)


# ---- CPC parameters (mirror src/params.rs) ----
m = 256                # ring dimension
q = 8380417            # modulus (NTT-friendly prime, q = 1 mod 512)
tau = 60               # challenge weight
beta_step = 45         # step l2 bound (beta in the paper)
sigma = 32400.0        # Gaussian width (12 * tau * beta)
B_resp = 622080        # response l2 bound (1.2 * sigma * sqrt(m))
sqrt_m = int(math.isqrt(m))   # 16

# ---- Two relevant norm bounds ----
# Theorem 1 (binding): nu = 2B + 2*tau*beta*sqrt(m)
nu_bind = 2 * B_resp + 2 * tau * beta_step * sqrt_m
# Theorem 3 (extraction): nu = 4*tau*sqrt(m)*B  (tighter bound from formal-proof.md)
nu_ext = 4 * tau * sqrt_m * B_resp
# src/params.rs EXTRACT_NORM_BOUND uses 4*tau*m*B (looser by factor m/sqrt(m)=16)
nu_code = 4 * tau * m * B_resp

# ---- SIS lattice parameters ----
# n = ring dimension (SIS output length, = number of scalar equations)
# m_lat = 2*n (NTRU-style lattice dimension, matches Dilithium parameterization)
n_sis = m        # 256
m_lat = 2 * m    # 512

print("=" * 72)
print("CPC Ring-SIS Core-SVP Estimation")
print("=" * 72)
print("Ring:   m=%d, q=%d (~2^%d), sqrt(m)=%d" % (m, q, q.bit_length() - 1, sqrt_m))
print("Params: tau=%d, beta=%d, sigma=%.1f, B=%d" % (tau, beta_step, sigma, B_resp))
print("SIS:    n=%d (output), m_lattice=%d (NTRU dim)" % (n_sis, m_lat))
print()
print("nu_bind = 2B + 2*tau*beta*sqrt(m) = %d  (~2^%d)" % (nu_bind, nu_bind.bit_length() - 1))
print("  nu_bind < q ? %s  (True => non-trivial SIS, security-critical)" % (nu_bind < q))
print("nu_ext  = 4*tau*sqrt(m)*B        = %d  (~2^%d)" % (nu_ext, nu_ext.bit_length() - 1))
print("  nu_ext  < q ? %s  (False => SIS trivially solvable; large-norm attack applies)" % (nu_ext < q))
print("nu_code = 4*tau*m*B              = %d  (~2^%d)  [src/params.rs EXTRACT_NORM_BOUND]"
      % (nu_code, nu_code.bit_length() - 1))
print()

results = {}


def estimate_for(nu, label):
    """Run BKZ estimation (Core-SVP / ADPS16 cost model, LGSA) for the given bound."""
    print("")
    print("--- %s: length_bound = nu = %d (~2^%d) ---" % (label, nu, nu.bit_length() - 1))
    params = SIS.Parameters(n=n_sis, q=q, length_bound=nu, norm=2, tag=label)
    print("  Parameters: %s" % params)
    try:
        # rough() uses Core-SVP cost model (ADPS16) + LGSA, comparable to literature
        res = SIS.estimate.rough(params)
        results[label] = {"length_bound": nu, "result": {k: str(v) for k, v in res.items()}}
        # Extract minimum log2 cost
        costs = []
        for alg, r in res.items():
            rop = None
            if isinstance(r, dict) and "rop" in r:
                rop = r["rop"]
            elif hasattr(r, "rop"):
                rop = r.rop
            if rop is not None and rop != oo:
                try:
                    costs.append((alg, float(rop)))
                except (TypeError, ValueError):
                    pass
        if costs:
            best = min(costs, key=lambda x: x[1])
            print("  => Best attack: %s, log2(rop) = %.1f" % (best[0], best[1]))
            if best[1] >= 128:
                print("  [PASS] Meets 128-bit target")
            else:
                print("  [BELOW] Below 128-bit target")
        else:
            print("  (Could not parse costs from estimator output above)")
    except Exception as e:
        print("  ERROR during estimation: %s" % e)
        results[label] = {"length_bound": nu, "error": str(e)}


estimate_for(nu_bind, "binding (nu_bind)")
estimate_for(nu_ext, "extraction (nu_ext)")

# Save results
with open("scripts/lattice_estimator_results.json", "w") as f:
    json.dump({
        "params": {
            "m": m, "q": q, "n_sis": n_sis, "m_lattice": m_lat,
            "tau": tau, "beta_step": beta_step, "sigma": sigma, "B": B_resp,
        },
        "norm_bounds": {
            "nu_bind": nu_bind,
            "nu_ext": nu_ext,
            "nu_code_EXTRACT_NORM_BOUND": nu_code,
        },
        "results": results,
    }, f, indent=2, default=str)

print("")
print("Results saved to scripts/lattice_estimator_results.json")
print("")
print("NOTE on quantum Core-SVP: rough() reports classical ADPS16 costs.")
print("For quantum Core-SVP, the standard approximation is to scale the BKZ")
print("block size beta by the ratio 0.265/0.292 ~ 0.908 (i.e. a ~9% smaller")
print("block size yields the quantum cost). See estimator.RC for quantum")
print("cost models (e.g. RC.ADPS16 with quantum sieving).")
