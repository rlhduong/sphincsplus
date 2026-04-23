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
    """Activate ``ctx`` so subsequent ``h``/``prf`` calls take the fast path.

    The pre-absorbed hashlib states from ``ctx`` and the output length ``n``
    are cached at module scope so the hot path in ``h``/``prf`` does not have
    to dereference the ``HashCtx`` object on every invocation. Call
    ``clear_hash_ctx`` before discarding ``ctx`` or activating a different one.

    Args:
        ctx: Pre-absorbed hash context to install as the active context.
    """
    global _active_ctx, _active_pk_base, _active_sk_base, _active_n, _active_is_shake
    _active_ctx = ctx
    _active_pk_base = ctx._pk_base
    _active_sk_base = ctx._sk_base
    _active_n = ctx._n
    _active_is_shake = ctx._is_shake


def clear_hash_ctx() -> None:
    """Tear down any active ``HashCtx`` and revert ``h``/``prf`` to the baseline path.

    Safe to call when no context is active; resets every module-level cache
    slot so a stale context cannot leak into later calls (which would
    silently produce wrong digests for the new parameter set).
    """
    global _active_ctx, _active_pk_base, _active_sk_base, _active_n, _active_is_shake
    _active_ctx = None
    _active_pk_base = None
    _active_sk_base = None
    _active_n = 0
    _active_is_shake = False


def get_hash_ctx() -> HashCtx | None:
    """Return the currently active ``HashCtx``, or ``None`` if the baseline path is in effect."""
    return _active_ctx


def _new_hash(params: Parameters):
    """Instantiate a fresh hashlib object for the hash function named by ``params``.

    Args:
        params: SPHINCS+ parameter set; only ``params.hash_fn`` is consulted.

    Returns:
        A new ``sha256``, ``sha512`` or ``shake_256`` object with no data absorbed.

    Raises:
        ValueError: If ``params.hash_fn`` is not one of the supported names.
    """
    if params.hash_fn == "sha256":
        return sha256()
    if params.hash_fn == "sha512":
        return sha512()
    if params.hash_fn == "shake":
        return shake_256()
    raise ValueError(f"Unsupported hash function: {params.hash_fn!r}")


def h_msg(
    r: bytes, pk_seed: bytes, pk_root: bytes, msg: bytes, params: Parameters
) -> bytes:
    """Compute ``H_msg(r, pk_seed, pk_root, msg)`` from the SPHINCS+ spec.

    For SHAKE parameter sets this is a single ``shake_256`` of
    ``r || pk_seed || pk_root || msg`` with output length ``params.m``.
    For SHA-2 parameter sets the spec prescribes an MGF1-like construction
    over ``r || pk_seed || H(r || pk_seed || pk_root || msg)`` to expand the
    fixed-length SHA digest to ``params.m`` bytes.

    Args:
        r: Per-signature randomiser (``n`` bytes) produced by ``prf_msg``.
        pk_seed: Public-key seed bound into every hash tweak.
        pk_root: Hypertree root, included to bind the digest to the public key.
        msg: Caller-supplied message to sign.
        params: Parameter set driving hash choice and digest length.

    Returns:
        The ``params.m``-byte message digest that feeds the FORS / hypertree.
    """
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
        c = counter.to_bytes(4, byteorder="big")
        mgf_hh = _new_hash(params)
        mgf_hh.update(mgf_seed)
        mgf_hh.update(c)
        out.extend(mgf_hh.digest())
        counter += 1
    return bytes(out[: params.m])


def h(pk_seed: bytes, adrs: ADRS, val: bytes, params: Parameters) -> bytes:
    """Tweakable hash ``H(pk_seed, ADRS, val)``.

    Implements two digest-equivalent paths:

    * **Fast path** — taken when a ``HashCtx`` is active via ``set_hash_ctx``.
      The cached pre-absorbed ``pk_seed`` hash state is cloned (one ``.copy()``
      of a C hashlib object) and only ``adrs.to_bytes()`` and ``val`` are fed
      in. Cuts out one Python-to-C transition and one ``update(pk_seed)`` call
      per invocation.
    * **Baseline path** — rebuilds a fresh hashlib object, absorbs the seed
      from scratch, and matches the reference-implementation semantics byte
      for byte.

    Args:
        pk_seed: Public-key seed. Ignored on the fast path (already absorbed).
        adrs: 32-byte address; serialised via ``adrs.to_bytes()``.
        val: Arbitrary-length payload mixed in after the address.
        params: Parameter set determining output length (``n`` bytes) and
            whether to use fixed-output SHA or variable-output SHAKE.

    Returns:
        ``n``-byte tweakable hash digest.
    """
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
    return hh.digest(params.n) if params.hash_fn == "shake" else hh.digest()[: params.n]


def h_adrs_bytes(
    pk_seed: bytes, adrs_bytes: bytes, val: bytes, params: Parameters
) -> bytes:
    """Optimisation 4 - ADRS snapshot variant of :func:`h`.

    Identical digest to ``h(pk_seed, adrs, val, params)`` when
    ``adrs_bytes == adrs.to_bytes()``.

    Call sites that previously wrote ``h(pk_seed, adrs.copy(), val, params)``
    can substitute ``h_adrs_bytes(pk_seed, adrs.to_bytes(), val, params)``
    to eliminate the intermediate ``ADRS`` object allocation and the associated
    ``bytearray(32)`` copy. On ``sphincs-sha2-128s`` this fires ~32 000 times
    per ``spx_sign`` (once per interior Merkle node across all XMSS trees) and
    a further ``h_prime`` times per ``spx_verify`` auth-path reconstruction.

    Args:
        pk_seed: Public-key seed (ignored when a ``HashCtx`` is active).
        adrs_bytes: The already-serialised 32-byte address.
        val: Arbitrary-length payload mixed in after the address.
        params: Parameter set determining output length and hash function.

    Returns:
        ``n``-byte tweakable hash digest, bit-identical to ``h``.
    """
    if _active_pk_base is not None:
        c = _active_pk_base.copy()
        c.update(adrs_bytes)
        c.update(val)
        if _active_is_shake:
            return c.digest(_active_n)
        return c.digest()[:_active_n]
    hh = _new_hash(params)
    hh.update(pk_seed)
    hh.update(adrs_bytes)
    hh.update(val)
    return hh.digest(params.n) if params.hash_fn == "shake" else hh.digest()[: params.n]


def prf(sk_seed: bytes, adrs: ADRS, params: Parameters) -> bytes:
    """Secret-keyed tweakable PRF ``PRF(sk_seed, ADRS)``.

    Used by WOTS+ and FORS to derive the per-address secret chain/leaf values.
    When a ``HashCtx`` with ``sk_seed`` pre-absorbed is active, takes the same
    fast path as ``h`` with one fewer ``.update`` call (no ``val`` input).

    Args:
        sk_seed: Secret-key seed. Ignored on the fast path.
        adrs: 32-byte address keying this PRF invocation.
        params: Parameter set determining output length and hash function.

    Returns:
        ``n``-byte pseudorandom output.
    """
    if _active_sk_base is not None:
        c = _active_sk_base.copy()
        c.update(adrs.to_bytes())
        if _active_is_shake:
            return c.digest(_active_n)
        return c.digest()[:_active_n]
    hh = _new_hash(params)
    hh.update(sk_seed)
    hh.update(adrs.to_bytes())
    return hh.digest(params.n) if params.hash_fn == "shake" else hh.digest()[: params.n]


def prf_msg(sk_seed: bytes, opt: bytes, msg: bytes, params: Parameters) -> bytes:
    """Derive the per-signature randomiser ``R = PRF_msg(sk_prf, opt, msg)``.

    ``opt`` is either ``pk_seed`` (deterministic mode, controlled by
    ``params.RANDOMIZE``) or a fresh 32-byte random string from ``secrets``.
    Always takes the baseline path: ``sk_prf`` is unique per signature and
    never benefits from pre-absorption.

    Args:
        sk_seed: The ``sk_prf`` half of the SPHINCS+ secret key.
        opt: Optional randomness input (see note above).
        msg: Message being signed.
        params: Parameter set determining output length and hash function.

    Returns:
        ``n``-byte per-signature randomiser ``R`` written into the signature.
    """
    hh = _new_hash(params)
    hh.update(sk_seed)
    hh.update(opt)
    hh.update(msg)
    return hh.digest(params.n) if params.hash_fn == "shake" else hh.digest()[: params.n]
