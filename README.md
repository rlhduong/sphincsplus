# SPHINCS+ in Python — baseline + implementation optimisations

A Python implementation of the NIST-standardised SPHINCS+ (SLH-DSA) stateless
hash-based signature scheme, with four stacked implementation-level
optimisations and a benchmark harness to quantify each one's contribution.

The baseline follows the [SPHINCS+ spec (eprint 2019/1086)](https://eprint.iacr.org/2019/1086.pdf). No external dependencies — just Python's standard library.

---

## Project layout

```
sphincsplus/
├── src/
│   ├── parameters.py   # Parameter sets (sha2-128s/f, shake-128s/f, 192*, 256*)
│   ├── address.py      # 32-byte tweakable-hash ADRS (optimised in-place layout)
│   ├── hash.py         # h, prf, h_msg, prf_msg + HashCtx hooks + h_adrs_bytes
│   ├── hash_ctx.py     # Pre-absorbed hashlib state (Opt-2)
│   ├── wots.py         # WOTS+ one-time signatures
│   ├── xmss.py         # XMSS Merkle tree + auth path (Opt-4 toggle here)
│   ├── fors.py         # FORS few-time signatures
│   ├── hypertree.py    # d-layer XMSS hypertree
│   ├── sphincs.py      # Top-level keygen / sign / verify
│   ├── group_sig.py    # DGSP group signature scheme
│   └── utils.py        # base_w, first_bits, byte helpers
├── tests/
│   ├── test_wots.py
│   ├── test_xmss.py
│   ├── test_fors.py
│   ├── test_hypertree.py
│   ├── test_sphincs.py
│   └── test_optimisation.py   # Parity tests: all opt paths produce
│                              # byte-identical signatures
├── bench.py            # 3-way benchmark harness (baseline / opt123 / opt1234)
├── bench_output.txt    # Most recent benchmark numbers
├── profile_final.txt   # Most recent cProfile snapshot (baseline sign)
├── conftest.py         # Pytest bootstrap: puts repo root on sys.path
└── README.md
```

---

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install pytest
.venv/bin/pytest tests/ -v                            # all 10 tests must pass
.venv/bin/python3 bench.py                            # 3-way bench on sphincs-sha2-128s
.venv/bin/python3 bench.py --full                     # all SHA-2 sets
.venv/bin/python3 bench.py --iters-sign 10            # more iterations
.venv/bin/python3 bench.py --profile                  # adds cProfile top-20 for baseline
```

The only runtime dependency is Python's standard library (`hashlib`,
`secrets`, `struct`, `math`). `pytest` is required only for tests.

---

## Part 1 — SPHINCS+ baseline + optimisations

### What SPHINCS+ is

SPHINCS+ is a stateless hash-based signature scheme. "Stateless" means you can sign as many messages as you want with the same key without tracking how many you've signed, unlike older hash-based schemes like XMSS. The security relies entirely on standard hash function properties (second preimage resistance), which makes it a conservative choice for post-quantum security.

The scheme is built in layers:

Four optimisations were added on top of the baseline SPHINCS+ code. **All are
implementation-level** (no cryptographic change) and the parity tests in
`tests/test_optimisation.py` assert that every optimised path produces
**byte-identical** signatures to the baseline.

---

The top-level API is in `src/sphincs.py`:

**Problem:** The original ADRS maintained eight separate `bytearray` fields
and rebuilt a fresh 32-byte buffer inside `to_bytes()` by copying each field
into a type-dependent slice on every call. On `sphincs-sha2-128s` that
function is called ~2.2 million times per `spx_sign`, and it was the
second-largest contributor to total signing time (~28% in the baseline
cProfile snapshot).

**Fix:** Maintain a single persistent `bytearray(32)` and mutate it in place
with `struct.pack_into`. `to_bytes()` becomes a single `bytes(self._buf)`
copy. `__slots__` eliminates the per-instance `__dict__`.

**Gain:** ~2× on its own (keygen: 439 ms → 216 ms, sign: 3590 ms → 1749 ms).

---

### Optimisation 2 — Pre-absorbed `HashCtx` (`src/hash_ctx.py`, `src/hash.py`)

**Problem:** Inside a single `spx_sign` call, the same `pk_seed` is the first
input to every `h(pk_seed, ADRS, val)`, and the same `sk_seed` is the first
input to every `prf(sk_seed, ADRS)`. The reference C implementation therefore
pre-absorbs each seed once and clones that state (`.copy()`) per call. In
pure Python, absorbing the seed fresh on every call costs a new `sha256()`
object construction plus a `→C boundary .update(seed)` call — repeated
millions of times.

**Fix:** `HashCtx` pre-absorbs `pk_seed` (and optionally `sk_seed`) into a
hashlib object. Module-level globals (`_active_pk_base`, `_active_sk_base`,
etc.) cache the handles so the hot path in `h()` / `prf()` uses a single
`.copy()` + `.update(adrs + val)` with no extra dispatch overhead.

Toggled via:
```python
from src import sphincs
sphincs.set_optimised(True)   # default: True
sphincs.set_optimised(False)  # revert to per-call sha256() path
```

**Gain:** ~1.10× on top of Opt-1.

---

The first version of the HashCtx hook went through a method call on the HashCtx object, which added a Python stack frame on every hash call. Caching the hashlib handle directly at module scope (`_active_pk_base`, `_active_sk_base`) and inlining the fast path into `h()` and `prf()` removed that overhead.

**Problem:** The first `HashCtx` hook added an extra Python stack frame
(one for `hash.h` → one for `HashCtx.h`), costing ~0.6 s per sign.

**Fix:** Cache the pre-absorbed handles directly at module scope
(`_active_pk_base`, `_active_sk_base`, `_active_n`, `_active_is_shake`) and
inline the fast path into `hash.h` / `hash.prf`, eliminating the inner frame.

Hardware: Apple Silicon, Python 3.14.3, single-threaded, `RANDOMIZE=False`, parameter set `sphincs-sha2-128s`.

### Optimisation 4 — ADRS snapshot: `h_adrs_bytes()` *(novel)*

**Problem:** The XMSS `treehash` function and `xmss_pk_from_sig` previously
used the pattern:

```python
node = h(pk_seed, adrs.copy(), left + right, params)
```

The `adrs.copy()` allocates a brand-new ADRS object (Python object header +
`bytearray(32)`), and then `h()` immediately calls `to_bytes()` on it to get
a `bytes(32)` snapshot for the hash input — a second allocation. The copy is
only needed to prevent `h()` from aliasing the live `adrs`; it is otherwise
discarded after the hash call. On `sphincs-sha2-128s` this pattern fires at
every interior Merkle node:

| Site | Calls per `spx_sign` |
|---|---|
| `treehash` interior nodes (all XMSS trees, all hypertree layers) | ~32 000 |
| `xmss_pk_from_sig` auth-path nodes (verify) | h_prime × d |

That is ~32 000 unnecessary ADRS object allocations per sign, each involving
a `bytearray(32)` copy, purely to extract 32 bytes that are then handed
straight to `hashlib`.

**Fix:** Add `h_adrs_bytes(pk_seed, adrs_bytes, val, params)` to `src/hash.py`:

```python
def h_adrs_bytes(pk_seed: bytes, adrs_bytes: bytes, val: bytes, params: Parameters) -> bytes:
    """Drop-in for h() when the caller already holds adrs.to_bytes()."""
    if _active_pk_base is not None:        # HashCtx fast path
        c = _active_pk_base.copy()
        c.update(adrs_bytes)
        c.update(val)
        return c.digest()[:_active_n]
    hh = _new_hash(params)                 # baseline path
    hh.update(pk_seed)
    hh.update(adrs_bytes)
    hh.update(val)
    return hh.digest()[: params.n]
```

Then replace each `h(pk_seed, adrs.copy(), val, params)` in `xmss.py` with:

```python
h_adrs_bytes(pk_seed, adrs.to_bytes(), val, params)
```

`adrs.to_bytes()` is `bytes(self._buf)` — a single C-level memcpy into an
immutable bytes object with no Python object overhead on the ADRS side.
No ADRS object is allocated; the snapshot is passed directly into the hash.

**Why this is correct:** `h()` never mutates its `adrs` argument; it only
reads `adrs.to_bytes()`. Pre-serialising outside the call is semantically
identical.

**Controlled by:** `src/xmss.ADRS_SNAPSHOT` (default `True`); the bench
harness sets it to `False` for the `opt123` column to isolate Opt-4's
contribution.

Fixing the ADRS made the code spec-compliant and exposed three pre-existing bugs:

## 4. How all paths stay byte-identical

`tests/test_optimisation.py` contains four tests:

| Test | What it checks |
|---|---|
| `test_optimised_roundtrip` | Sign + verify round-trip with all opts on |
| `test_baseline_and_optimised_produce_identical_signatures` | keygen, sign, and cross-verify are byte-equal between `optimised=False` and `optimised=True` |
| `test_h_adrs_bytes_matches_h` | `h_adrs_bytes(pk_seed, adrs.to_bytes(), val)` == `h(pk_seed, adrs, val)` for **every AdrsType**, both with and without a HashCtx active |
| `test_opt4_end_to_end` | Full sign/verify round-trip with `ADRS_SNAPSHOT=True` and a deterministic seed |

All 10 tests pass.

---

## 5. Benchmark results

Hardware: Apple Silicon (M-series), Python 3.13.3, single-threaded,
`RANDOMIZE=False`. Parameter set: `sphincs-sha2-128s` (NIST Level 1).

Measured with `bench.py --iters-keygen 5 --iters-sign 8 --iters-verify 30`.

### 5.1 Three-way comparison

| Operation | baseline (ms) | opt123 (ms) | opt1234 (ms) | vs baseline | Opt-4 gain |
|-----------|-------------:|------------:|-------------:|:-----------:|:----------:|
| keygen    | 188.1        | 171.0       | 170.6        | **1.10×**   | 1.002×     |
| sign      | 1532.2       | 1420.0      | 1401.1       | **1.09×**   | **1.013×** |
| verify    | 1.49         | 1.49        | 1.34         | **1.11×**   | **1.115×** |

* **opt123** = Opt-1 (mutable ADRS) + Opt-2 (HashCtx) + Opt-3 (inlined dispatch)
* **opt1234** = opt123 + **Opt-4 (ADRS snapshot)**

**Opt-4 analysis:**

- **Sign:** 1.3% additional speedup on top of opt123. The effect is modest
  because the interior-node hash calls (~32 000) are dwarfed by the WOTS+
  chain calls (~2 million) that already dominate sign time.
- **Verify:** **11.5% speedup**, and this is the more interesting result.
  During verification the auth-path reconstruction in `xmss_pk_from_sig` is
  the *majority* of the work (WOTS+ pk-from-sig is relatively cheap), so the
  `h_adrs_bytes` path — which fires for every auth-path node — removes a
  proportionally large fraction of the remaining allocations.
- **Keygen:** Negligible (0.2%), dominated by the same WOTS+ chains as sign.

### 5.2 Cumulative speedup (all four optimisations)

Starting from the very first unoptimised run (before Opt-1 even):

| Operation | Pre-Opt-1 (ms) | Final opt1234 (ms) | Total speedup |
|-----------|---------------:|-------------------:|--------------:|
| keygen    | 438.9          | 170.6              | **2.57×**     |
| sign      | 3590.0         | 1401.1             | **2.56×**     |
| verify    | 3.35           | 1.34               | **2.50×**     |

### 5.3 Why Opt-4 is most visible in verify

A `spx_verify` does almost no WOTS+ chain work (it recomputes the WOTS+ pk
from the sig in O(wots_len) chain steps rather than re-hashing the whole
tree). The dominant cost is the Merkle path reconstruction:
`h_prime × d = 9 × 7 = 63` interior-node hashes on `sphincs-sha2-128s`.
Each of those previously allocated an ADRS object; Opt-4 removes all 63
of them. Since 63 calls represent nearly the *entire* verify workload (unlike
sign where 32 000 are swamped by 2 million WOTS+ calls), the speedup is
disproportionately large for verify.

**Verification**

The verifier reconstructs the WOTS+ public key from the signature, then checks the manager's SPHINCS+ certificate on it. No user identity is revealed.

```python
ok = verify(message, sig, revoked_set, mpk, params)
```

| File | Fix |
|---|---|
| `src/fors.py` (`fors_treehash`) | Added `adrs.set_tree_height(0)` / `adrs.set_tree_index(s+i)` before the leaf hash. |
| `tests/test_fors.py` (`adrs` fixture) | Changed fixture from `AdrsType.WOTS_HASH` to `AdrsType.FORS_TREE`. |
| `src/hash.py` (SHAKE digest size) | `.digest()` without a length raises on `shake_256`; fixed to `.digest(params.n)`. |

```python
honest = judge(sig, message, uid, pi, params)
```

**Revocation**

```bash
# 1. Create a virtualenv and install pytest
python3 -m venv .venv
.venv/bin/pip install pytest

# 2. Run all 10 tests
.venv/bin/pytest tests/ -v

# 3. Quick 3-way benchmark
.venv/bin/python3 bench.py

# 4. Tighter numbers (slower)
.venv/bin/python3 bench.py --iters-keygen 10 --iters-sign 15 --iters-verify 60

# 5. Include cProfile output for baseline sign
.venv/bin/python3 bench.py --profile

# 6. Toggle optimisations manually
python3 -c "
import src.xmss as xmss_mod, src.sphincs as sphincs_mod
sphincs_mod.set_optimised(False)   # disable HashCtx
xmss_mod.ADRS_SNAPSHOT = False     # disable Opt-4
"
```

---

## Running everything

| Optimisation | What it does | Main gain |
|---|---|---|
| **Opt-1** Mutable ADRS buffer | Single `bytearray(32)` mutated in-place; `to_bytes()` = one memcpy | ~2× keygen/sign/verify |
| **Opt-2** Pre-absorbed HashCtx | Seed absorbed once; each call does `.copy()` + `update(adrs+val)` only | ~1.10× additional |
| **Opt-3** Inlined dispatch | HashCtx handles cached at module scope, no extra stack frame | Baked into Opt-2 |
| **Opt-4** ADRS snapshot *(novel)* | `h_adrs_bytes()` takes `adrs.to_bytes()` directly, removing `adrs.copy()` object allocations at every interior Merkle node | +1.0–1.1× (most visible in verify: **+11.5%**) |

**Combined: 2.5× faster than the unoptimised baseline, all paths
producing byte-identical signatures.**
