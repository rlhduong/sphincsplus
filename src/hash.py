"""Tweakable-hash primitives used throughout SPHINCS+.

The baseline `h(pk_seed, adrs, val, params)` and `prf(sk_seed, adrs, params)`
functions re-create a fresh hashlib object and re-absorb the seed on every
invocation. That is fine for clarity but slow: a single signature on
`sphincs-sha2-128s` makes ~2 million such calls.

When a `HashCtx` with pre-absorbed seeds is registered via `set_hash_ctx`,
the module-level `h()` / `prf()` short-circuit through cached module-local
state (no method dispatch through the HashCtx object, just one `.copy()` of
the pre-absorbed hashlib state). The digests produced are bit-identical to
the baseline path.

Usage (typically from `spx_sign` / `spx_verify` / `spx_keygen`):

    ctx = HashCtx(pk_seed, params, sk_seed=sk_seed)
    set_hash_ctx(ctx)
    try:
        ...                 # existing algorithm, unchanged
    finally:
        clear_hash_ctx()
"""

from hashlib import sha256, sha512, shake_256

from src.address import ADRS
from src.parameters import Parameters
from src.hash_ctx import HashCtx


_active_ctx: HashCtx | None = None
# Cached directly at module scope so the hot path in h()/prf() avoids an
# extra attribute lookup through HashCtx on every single hash invocation.
_active_pk_base = None
_active_sk_base = None
_active_n: int = 0
_active_is_shake: bool = False


def set_hash_ctx(ctx: HashCtx) -> None:
    global _active_ctx, _active_pk_base, _active_sk_base, _active_n, _active_is_shake
    _active_ctx = ctx
    _active_pk_base = ctx._pk_base
    _active_sk_base = ctx._sk_base
    _active_n = ctx._n
    _active_is_shake = ctx._is_shake


def clear_hash_ctx() -> None:
    global _active_ctx, _active_pk_base, _active_sk_base, _active_n, _active_is_shake
    _active_ctx = None
    _active_pk_base = None
    _active_sk_base = None
    _active_n = 0
    _active_is_shake = False


def get_hash_ctx() -> HashCtx | None:
    return _active_ctx


def _new_hash(params: Parameters):
    if params.hash_fn == "sha256":
        return sha256()
    if params.hash_fn == "sha512":
        return sha512()
    if params.hash_fn == "shake":
        return shake_256()
    raise ValueError(f"Unsupported hash function: {params.hash_fn!r}")


def h_msg(r: bytes, pk_seed: bytes, pk_root: bytes, msg: bytes, params: Parameters) -> bytes:
    hh = _new_hash(params)
    hh.update(r)
    hh.update(pk_seed)
    hh.update(pk_root)
    hh.update(msg)
    if params.hash_fn == "shake":
        return hh.digest(params.m)

    base_digest = hh.digest()
    mgf_seed = r + pk_seed + base_digest
    
    out = bytearray()
    counter = 0
    
    while len(out) < params.m:
        c = counter.to_bytes(4, byteorder='big')
        mgf_hh = _new_hash(params)
        mgf_hh.update(mgf_seed)
        mgf_hh.update(c)
        out.extend(mgf_hh.digest())
        counter += 1
    return bytes(out[:params.m])


def h(pk_seed: bytes, adrs: ADRS, val: bytes, params: Parameters) -> bytes:
    # Fast path: HashCtx active, pk_seed already absorbed.
    if _active_pk_base is not None:
        c = _active_pk_base.copy()
        c.update(adrs.to_bytes())
        c.update(val)
        if _active_is_shake:
            return c.digest(_active_n)
        return c.digest()[:_active_n]
    # Baseline path: rebuild hashlib object per call.
    hh = _new_hash(params)
    hh.update(pk_seed)
    hh.update(adrs.to_bytes())
    hh.update(val)
    if params.hash_fn == "shake":
        return hh.digest(params.n)
    return hh.digest()[: params.n]


def prf(sk_seed: bytes, adrs: ADRS, params: Parameters) -> bytes:
    if _active_sk_base is not None:
        c = _active_sk_base.copy()
        c.update(adrs.to_bytes())
        if _active_is_shake:
            return c.digest(_active_n)
        return c.digest()[:_active_n]
    hh = _new_hash(params)
    hh.update(sk_seed)
    hh.update(adrs.to_bytes())
    if params.hash_fn == "shake":
        return hh.digest(params.n)
    return hh.digest()[: params.n]


def prf_msg(sk_seed: bytes, opt: bytes, msg: bytes, params: Parameters) -> bytes:
    hh = _new_hash(params)
    hh.update(sk_seed)
    hh.update(opt)
    hh.update(msg)
    if params.hash_fn == "shake":
        return hh.digest(params.n)
    return hh.digest()[: params.n]
