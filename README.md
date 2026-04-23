# SPHINCS+ in Python

A Python implementation of SPHINCS+ (also known as SLH-DSA, standardised by NIST as FIPS 205), extended with a group signature scheme based on [DGSP (eprint 2025/760)](https://eprint.iacr.org/2025/760).

The baseline follows the [SPHINCS+ spec (eprint 2019/1086)](https://eprint.iacr.org/2019/1086.pdf). No external dependencies just Python's standard library.

## Project layout

```
sphincsplus/
├── src/
│   ├── parameters.py   # Parameter sets (sha2/shake × 128/192/256 × s/f)
│   ├── address.py      # 32-byte ADRS tweakable-hash address
│   ├── hash.py         # h, prf, h_msg, prf_msg + HashCtx caching
│   ├── hash_ctx.py     # Pre-absorbed hashlib state
│   ├── wots.py         # WOTS+ one-time signatures
│   ├── xmss.py         # XMSS Merkle tree
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
│   ├── test_optimisation.py
│   └── test_group_sig.py
├── bench.py
├── bench_output.txt
├── profile_final.txt
└── conftest.py
```


## Quick start

```bash
python -m venv .venv
.venv/bin/pip install pytest
.venv/bin/pytest tests/ -v
.venv/bin/python bench.py
```


## Part 1: SPHINCS+ baseline + optimisations

### What SPHINCS+ is

SPHINCS+ is a stateless hash-based signature scheme. "Stateless" means you can sign as many messages as you want with the same key without tracking how many you've signed, unlike older hash-based schemes like XMSS. The security relies entirely on standard hash function properties (second preimage resistance), which makes it a conservative choice for post-quantum security.

The scheme is built in layers:

- **WOTS+** signs a single fixed-length message by chaining hash evaluations. It's one-time, so it's never used directly.
- **XMSS** uses a Merkle tree to let you use many WOTS+ keys under a single public key.
- **FORS** handles the variable-length message digest at the bottom of the tree.
- **Hypertree** stacks multiple XMSS trees on top of each other so the public key stays small regardless of how many signatures are supported.

The top-level API is in `src/sphincs.py`:

```python
sk, pk = spx_keygen(params)
sig = spx_sign(message, sk, params)
ok  = spx_verify(message, sig, pk, params)
```

### Optimisations

Three optimisations were added on top of the baseline. None of them change the cryptography, a signature from the optimised path and the baseline path are byte-identical, which `tests/test_optimisation.py` checks.

**1. Mutable ADRS buffer (`src/address.py`)**

The original ADRS kept 8 separate `bytearray` fields and rebuilt a 32-byte buffer from scratch in `to_bytes()` on every call. During signing on `sphincs-sha2-128s`, that function gets called around 2.2 million times, and it accounted for 28% of total signing time. The fix was simple: keep a single persistent `bytearray(32)` and mutate it in-place with `struct.pack_into`. `to_bytes()` then just does `bytes(self._buf)`. This alone roughly doubled speed.

**2. Pre-absorbed HashCtx (`src/hash_ctx.py`, `src/hash.py`)**

Every call to `h(pk_seed, adrs, val)` was creating a fresh `hashlib.sha256()` object and feeding in `pk_seed` again. Since `pk_seed` is fixed for the entire signing operation, you can absorb it once and clone that state on each call instead. The `HashCtx` class holds these pre-absorbed states. Toggling this optimisation on/off:

```python
from src import sphincs
sphincs.set_optimised(True)   # on by default
sphincs.set_optimised(False)  # back to per-call sha256()
```

**3. Inlined dispatch (`src/hash.py`)**

The first version of the HashCtx hook went through a method call on the HashCtx object, which added a Python stack frame on every hash call. Caching the hashlib handle directly at module scope (`_active_pk_base`, `_active_sk_base`) and inlining the fast path into `h()` and `prf()` removed that overhead.

### Benchmark results

Hardware: Apple Silicon, Python 3.14.3, single-threaded, `RANDOMIZE=False`, parameter set `sphincs-sha2-128s`.

| Operation | Before any optimisation | Final | Speedup |
|-----------|------------------------:|------:|--------:|
| keygen    | 438.9 ms  | 190.0 ms | **2.31×** |
| sign      | 3590.0 ms | 1592.6 ms | **2.25×** |
| verify    | 3.35 ms   | 1.64 ms  | **2.04×** |

The ADRS refactor is responsible for most of the gain (~2×). HashCtx adds about another 10% on top.

The profiler shows that even after optimisation, 61% of signing time is inside `hash.h` (2 million calls). The remaining bottleneck is fundamentally the Python→C boundary on each hashlib call, you'd need a C extension or batching to push much further.

### Bug fixes

Fixing the ADRS made the code spec-compliant and exposed three pre-existing bugs:

- `src/fors.py` - missing `set_tree_height(0)` / `set_tree_index(s+i)` before the leaf hash, meaning `fors_pk_gen` and `fors_pk_from_sig` produced different leaf inputs.
- `tests/test_fors.py` - the ADRS fixture used `WOTS_HASH` type instead of `FORS_TREE`.
- `src/hash.py` - `shake_256().digest()` with no length argument raises an error. Fixed to pass `params.n` / `params.m`.

All imports were also changed from bare (`from address import ADRS`) to the `src.` prefix so pytest works from the repo root.

## Part 2: Group signature scheme (DGSP)

Implementation in `src/group_sig.py`, tests in `tests/test_group_sig.py`.

Based on: [DGSP: An Efficient Scalable Fully Dynamic Group Signature Scheme Using SPHINCS+](https://eprint.iacr.org/2025/760)

### What a group signature is

A group signature lets any member of a group sign a message on behalf of the group. From the verifier's perspective, the signature is valid and came from the group, but they can't tell which member signed it. There's a designated manager who holds a secret tracing key and can de-anonymise any signature if needed (e.g. if someone abuses the scheme). Members can also be revoked, and their past signatures can be retroactively blocked.

### How this implementation works

The manager holds a SPHINCS+ keypair. The core idea is that every group member signs messages using WOTS+ keys that the manager has certified with SPHINCS+. Verifiers check the certificate rather than knowing anything about who the user is.

**Joining the group**

The manager assigns a user ID and computes a cryptographic identity token (`cid_star`) derived from a secret `hash_secret`. The user stores this to prove their identity when requesting certificates later.

```python
mpk, msk = keygen_manager(params)
seed_u    = keygen_user(params)
uid, cid_star = join(msk, "alice", membership_list, params)
```

**Getting certificates**

The user generates a batch of WOTS+ keypairs and sends the public keys to the manager. The manager signs each one, embedding an encrypted `(user_id, counter)` blob called `zeta` that only the manager can decrypt. This is what enables tracing without revealing identity to verifiers.

```python
wots_pks, wots_seeds = csr(seed_u, 5, params)          # user generates 5 keypairs
certs = gen_cert(msk, uid, cid_star, wots_pks, ml, params)  # manager certifies them
```

Each certificate contains:
- `zeta` - encrypted `(user_id, counter)`, opaque to verifiers
- `pi` - hash binding the WOTS+ key to the user's identity
- `spx_sig` - manager's SPHINCS+ signature over the whole bundle

**Signing a message**

The user picks an unused `(wots_seed, cert)` pair (WOTS+ is one-time) and signs:

```python
sig = sign(message, seed_u, uid, wots_seeds[0], certs[0], params)
```

The signature contains the WOTS+ signature on the message, the `wots_seed` (so verifiers can reconstruct the public key), and the manager's certificate fields.

**Verification**

The verifier reconstructs the WOTS+ public key from the signature, then checks the manager's SPHINCS+ certificate on it. No user identity is revealed.

```python
ok = verify(message, sig, revoked_set, mpk, params)
```

**Tracing and accountability**

If the manager needs to identify who signed, they decrypt `zeta` to get the user ID:

```python
uid, username, pi = open_sig(msk, sig, message, membership_list, params)
```

A third party can then verify that the manager's claim is honest (i.e. the manager isn't falsely attributing the signature to someone):

```python
honest = judge(sig, message, uid, pi, params)
```

**Revocation**

Revoking a user means computing all their past `zeta` values and adding them to a public revoked set. Any signature with a revoked `zeta` fails verification.

```python
revoke(msk, [uid], membership_list, revoked_set, params)
```

### Security properties

- **Unforgeability**: you can't produce a valid group signature without a manager-issued certificate, which relies on the unforgeability of SPHINCS+.
- **Anonymity**: verifiers see only `zeta` (which looks random without the tracing key) and a SPHINCS+ signature on the certificate message. Nothing links to a specific user.
- **Traceability**: the manager can always recover `user_id` from `zeta` by decryption, and `judge` lets anyone check the claim.
- **Forward anonymity**: revoking a user doesn't de-anonymise their past signatures, it just makes future verifications of their signatures fail.

### Encryption note

The Rust reference implementation uses AES-128-ECB for `zeta` encryption. Since this project uses only the standard library, a 4-round Feistel cipher built on SHA-256 is used instead. It has the same properties needed for the construction: deterministic, invertible by the manager, and opaque to verifiers.

### Tests

```
tests/test_group_sig.py - 6 tests, all pass in ~7s on sphincs-sha2-128s
```

Covers: sign/verify roundtrip, wrong message rejection, revocation, open+judge, invalid `cid_star` rejection, and two independent users in the same group.


## Running everything

```bash
# All tests
pytest tests/ -v

# Just group sig tests
pytest tests/test_group_sig.py -v

# Benchmark (keygen / sign / verify)
python bench.py

# More iterations for tighter numbers
python bench.py --iters-keygen 10 --iters-sign 15 --iters-verify 60

# cProfile snapshot of baseline sign
python bench.py --profile
```
