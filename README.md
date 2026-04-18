# SPHINCS+ in Python — baseline + hash-context optimisation

A Python implementation of the NIST-standardised SPHINCS+ (SLH-DSA) stateless
hash-based signature scheme, plus a pre-absorbed hash-context optimisation
and a benchmark harness to quantify the speedup.

The reference design follows [SPHINCS+ (eprint 2019/1086)](https://eprint.iacr.org/2019/1086.pdf).

---

## 1. Project layout

```
sphincsplus/
├── src/
│   ├── parameters.py   # Parameter sets (sha2-128s/f, shake-128s/f, 192*, 256*)
│   ├── address.py      # 32-byte tweakable-hash ADRS (optimised in-place layout)
│   ├── hash.py         # h, prf, h_msg, prf_msg + HashCtx hooks
│   ├── hash_ctx.py     # Pre-absorbed hashlib state optimisation
│   ├── wots.py         # WOTS+ one-time signatures
│   ├── xmss.py         # XMSS Merkle tree + auth path
│   ├── fors.py         # FORS few-time signatures
│   ├── hypertree.py    # d-layer XMSS hypertree
│   ├── sphincs.py      # Top-level spx_keygen / spx_sign / spx_verify
│   └── utils.py        # base_w, first_bits, misc helpers
├── tests/
│   ├── test_wots.py
│   ├── test_xmss.py
│   ├── test_fors.py
│   ├── test_hypertree.py
│   ├── test_sphincs.py
│   └── test_optimisation.py   # Parity test: baseline vs optimised produce
│                              # byte-identical signatures
├── bench.py            # Benchmark harness (keygen / sign / verify)
├── bench_output.txt    # Most recent benchmark numbers
├── profile_final.txt   # Most recent cProfile snapshot (baseline sign)
├── conftest.py         # Pytest bootstrap: puts repo root on sys.path
└── README.md
```

---

## 2. Quick start

```bash
python -m venv .venv
.venv/bin/pip install pytest
.venv/bin/pytest tests/ -v                        # all 8 tests must pass
.venv/bin/python bench.py                         # default run on sphincs-sha2-128s
.venv/bin/python bench.py --profile               # adds baseline cProfile top-20
.venv/bin/python bench.py --iters-sign 10         # more iterations
```

The only runtime dependency is Python's standard library (`hashlib`,
`secrets`, `struct`, `math`). `pytest` is required only for running the
tests.

---

## 3. What was implemented

Three optimisations were added on top of the baseline SPHINCS+ code. All three
are **implementation-level** (no cryptographic change) and the parity test in
`tests/test_optimisation.py` asserts that the optimised path produces
**byte-identical** signatures to the baseline path.

### Optimisation 1 — In-place mutable ADRS buffer (`src/address.py`)

The old ADRS maintained eight separate `bytearray` fields (`layer`, `tree`,
`type`, `key_pair`, `chain`, `hash`, `tree_index`, `tree_height`) and rebuilt
a fresh 32-byte buffer inside `to_bytes()` by copying each field into a type-
dependent slice on every call. On `sphincs-sha2-128s` that function is called
~2.2 million times per `spx_sign`, and it was the second-largest contributor
to total signing time (28% in the original cProfile snapshot).

The refactor keeps a single persistent `bytearray(32)` inside each ADRS and
mutates it in place using `struct.pack_into`. `to_bytes()` is then a single
`bytes(self._buf)` copy. `copy()` is also simplified to clone one buffer.
`__slots__` eliminates the per-instance `__dict__`.

**Side benefit:** this also fixed a latent byte-length bug in the original
ADRS (see §6 — Bug fixes found during refactor).

### Optimisation 2 — Pre-absorbed `HashCtx` (`src/hash_ctx.py`, `src/hash.py`)

Inside a single `spx_sign` call the same `pk_seed` is fed as the first input
to every `h(pk_seed, ADRS, val)`, and the same `sk_seed` is fed as the first
input to every `prf(sk_seed, ADRS)`. The reference SPHINCS+ C implementation
therefore creates a hashlib state with the seed already absorbed once, and
clones that state (`.copy()`) for each call. In pure Python this saves, per
hash invocation:

* constructing a fresh `hashlib.sha256()` object,
* the Python→C boundary call `.update(seed)` that re-absorbs the seed, and
* an intermediate `_new_hash(params)` dispatch.

We expose this as a toggle:

```python
from src import sphincs
sphincs.set_optimised(True)   # default: True
sphincs.set_optimised(False)  # drop back to the per-call sha256() path
```

When enabled, `spx_keygen`, `spx_sign`, and `spx_verify` wrap their body in
`set_hash_ctx(...) / clear_hash_ctx()`. The module-level `h()` and `prf()`
then short-circuit through a module-local cached handle for minimal dispatch
overhead (no method call through the `HashCtx` object in the hot path).

### Optimisation 3 — Inlined dispatch in `h()` / `prf()` (`src/hash.py`)

The first version of the `HashCtx` hook added a second Python stack frame
(one for `hash.h` → one for `HashCtx.h`), which cost ~0.6 s of the ~5 s
measured sign. Caching the pre-absorbed `hashlib` handle directly at module
scope (`_active_pk_base`, `_active_sk_base`, `_active_n`, `_active_is_shake`)
and inlining the fast path into `hash.h` / `hash.prf` saves that frame.

---

## 4. How the two paths stay byte-identical

The test `tests/test_optimisation.py::test_baseline_and_optimised_produce_identical_signatures`
monkey-patches `secrets.token_bytes` with a deterministic replacement,
disables `params.RANDOMIZE` so `spx_sign` is deterministic, then:

1. Calls `spx_keygen` under both paths and asserts the key pairs match.
2. Signs the same message under each path and asserts the signatures are
   byte-equal.
3. Cross-verifies: a signature from `optimised=True` verifies under
   `optimised=False`, and vice versa.

If any of these diverge, the test fails. This is the correctness guarantee
for the optimisation.

---

## 5. Benchmark results

Hardware: Apple Silicon, Python 3.14.3, single-threaded, `RANDOMIZE=False`.

Parameter set: `sphincs-sha2-128s` (the fast-to-verify NIST Level 1 set used
by the existing `test_sphincs.py`).

### 5.1 End-to-end speedup

Measured with `bench.py --iters-keygen 5 --iters-sign 8 --iters-verify 30`.
Medians after trimming best/worst.

| Operation | Baseline (ms) | Optimised (ms) | Speedup (this PR) |
|-----------|--------------:|---------------:|------------------:|
| keygen    | 216.0         | 190.0          | **1.14×**         |
| sign      | 1749.1        | 1592.6         | **1.10×**         |
| verify    | 1.82          | 1.64           | **1.10×**         |

Here "baseline" means `sphincs.set_optimised(False)` and "optimised" means
`sphincs.set_optimised(True)`. Both columns include the mutable-ADRS
refactor (§Optimisation 1) because that change is not gated by the flag.

### 5.2 Cumulative speedup including the ADRS refactor

The very first run (before any optimisation) produced:

| Operation | Pre-refactor (ms) | Final optimised (ms) | Total speedup |
|-----------|------------------:|---------------------:|--------------:|
| keygen    | 438.9             | 190.0                | **2.31×**     |
| sign      | 3590.0            | 1592.6               | **2.25×**     |
| verify    | 3.35              | 1.64                 | **2.04×**     |

i.e. the mutable ADRS buffer is by far the bigger win on its own (~2× on its
own); the pre-absorbed HashCtx then peels off another ~10%.

### 5.3 Where the remaining time goes

A cProfile snapshot of the baseline `spx_sign` (taken with
`bench.py --profile`, saved to `profile_final.txt`) shows:

```
ncalls      cumtime     function
      1       5.73     sphincs.spx_sign
      1       4.86     hypertree.hypertree_sign
      7       4.85     xmss.xmss_sign
     63       4.85     xmss.treehash
   3577      4.81     wots.wots_gen_pk
 125650      4.29     wots.chain
2003156      3.51    hash.h              <-- 2.0M calls, 61% of total
2185942      0.55    hashlib.digest
2185942      0.63    _new_hash
```

The inner hot path is almost entirely `wots.chain → hash.h → hashlib`. Future
work could attack the remaining 3.5 s of `hash.h` cumulative time by batching
`chain()` iterations or implementing `F / H / T_l` in a C extension, but
that's outside the scope of this project.

---

## 6. Bug fixes found during the refactor

Making `ADRS.to_bytes()` spec-compliant surfaced three latent bugs in the
upstream code. All of them were silent under the old "type-dependent, partial
serialisation" implementation of ADRS and would have made the code fail on
any spec-compliant verifier.

| File | Fix |
|---|---|
| `src/fors.py` (`fors_treehash`) | Added `adrs.set_tree_height(0)` / `adrs.set_tree_index(s+i)` **before** the leaf hash so `fors_pk_gen` produces the same leaf input as `fors_pk_from_sig`. |
| `tests/test_fors.py` (`adrs` fixture) | Changed fixture from `AdrsType.WOTS_HASH` to `AdrsType.FORS_TREE` to match what the real `spx_sign` call site uses. |
| `src/hash.py` (SHAKE digest size) | `.digest()` without a length argument raises on `shake_256`; the baseline would have crashed on any `shake-*` parameter set. Fixed by using `.digest(params.n)` / `.digest(params.m)` when `hash_fn == 'shake'`. |

Additionally, every module under `src/` used bare imports (`from address
import ADRS`) instead of the `src.` prefix, which broke `pytest` invocations
from the repo root. All imports have been normalised to `from src.<module>
import …`, and `conftest.py` ensures the repo root is on `sys.path`.

One known **pre-existing** limitation kept out of scope: `sphincs-sha2-128f`
and `sphincs-shake-128s` specify an `m`-byte message digest that doesn't fit
in the selected hash function's output (e.g. `sha256` gives 32 B but the
parameter set requires 34 B). These parameter sets are excluded from the
default bench targets until a multi-block `h_msg` construction is added.

---

## 7. Reproducing the numbers

```bash
# 1. Create a virtualenv and install pytest
python -m venv .venv
.venv/bin/pip install pytest

# 2. Run the parity + correctness tests
.venv/bin/pytest tests/ -v

# 3. Run the benchmark (defaults: sphincs-sha2-128s, 5/8/30 iters)
.venv/bin/python bench.py

# 4. Tighter numbers (slower):
.venv/bin/python bench.py --iters-keygen 10 --iters-sign 15 --iters-verify 60

# 5. Include cProfile output for baseline sign
.venv/bin/python bench.py --profile

# 6. Use the set_optimised() toggle from your own code
python -c "from src import sphincs; sphincs.set_optimised(False); ..."
```

Output is printed to stdout and mirrored to `bench_output.txt` by the
suggested pipeline in this README.

---

## 8. Summary

* Implemented SPHINCS+ end to end with a benchmark-driven optimisation pass.
* The big win (~2×) was a profile-driven refactor of `ADRS.to_bytes()`.
* The pre-absorbed `HashCtx` optimisation (the SPHINCS+ reference-level hot-
  path trick) stacks a further ~10% on top in pure Python.
* Correctness is enforced by a byte-level parity test across the two paths.
* Pre-existing latent bugs that the stricter ADRS exposed have been fixed.
