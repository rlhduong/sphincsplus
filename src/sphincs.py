"""Top-level SPHINCS+ API: ``spx_keygen`` / ``spx_sign`` / ``spx_verify``.

This module stitches FORS and the hypertree together and exposes the
public ``spx_*`` entry points. The module-level ``OPTIMISED`` flag gates
the pre-absorbed ``HashCtx`` fast path; ``set_optimised(False)`` falls
back to the reference behaviour and is used by benchmarks and tests.

Parsing helpers (``get_md``, ``get_idx_tree``, ``get_idx_leaf``) and
signature-slicing helpers (``get_r_from_sig``, ``get_sig_fors_from_sig``,
``get_sig_ht_from_sig``) implement the fixed layout defined in §7 of the
SPHINCS+ specification::

    signature = R || sig_fors || sig_ht
    |R|        = n bytes
    |sig_fors| = (a + 1) * k * n bytes
    |sig_ht|   = d * (wots_len + h_prime) * n bytes
"""

import secrets

from src.parameters import Parameters
from src.address import ADRS, AdrsType
from src.fors import fors_sign, fors_pk_from_sig
from src.hypertree import hypertree_gen_pk, hypertree_sign, hypertree_verify
from src.hash import h_msg, prf_msg, set_hash_ctx, clear_hash_ctx
from src.hash_ctx import HashCtx
from src.utils import first_bits


OPTIMISED = True


def set_optimised(flag: bool) -> None:
    """Toggle the pre-absorbed `HashCtx` optimisation at module scope.

    When True, `spx_keygen`, `spx_sign` and `spx_verify` build a `HashCtx`
    with `pk_seed` (and `sk_seed` where applicable) pre-absorbed and register
    it on `src.hash` so that every `h`/`prf` call short-circuits through the
    cached state. When False, the original per-call `sha256()` + `update(seed)`
    path is used and the optimisation is a no-op.

    The two paths are digest-equivalent, so signatures from one path verify
    under the other.
    """
    global OPTIMISED
    OPTIMISED = flag


def get_md(tmp_md: bytes, params: Parameters) -> int:
    """Extract the top ``k * log_t`` bits of ``tmp_md`` as an integer.

    This is the FORS message digest: ``k`` groups of ``log_t`` bits used to
    pick one leaf per FORS sub-tree.
    """
    return first_bits(tmp_md, params.k * params.log_t)


def get_idx_tree(tmp_idx_tree: bytes, params: Parameters) -> int:
    """Extract the hypertree index (``h - h/d`` bits) from the digest slice."""
    return first_bits(tmp_idx_tree, params.h - params.h // params.d)


def get_idx_leaf(tmp_idx_leaf: bytes, params: Parameters) -> int:
    """Extract the XMSS leaf index (``h/d`` bits) from the digest slice."""
    return first_bits(tmp_idx_leaf, params.h // params.d)


def get_r_from_sig(sig: bytes, params: Parameters) -> bytes:
    """Return the per-signature randomiser ``R`` (first ``n`` bytes of ``sig``)."""
    return sig[: params.n]


def get_sig_fors_from_sig(sig: bytes, params: Parameters) -> bytes:
    """Return the FORS sub-signature slice (``(a + 1) * k * n`` bytes after ``R``)."""
    return sig[params.n : params.n + (params.a + 1) * params.k * params.n]


def get_sig_ht_from_sig(sig: bytes, params: Parameters) -> bytes:
    """Return the hypertree sub-signature (the remainder of the signature after FORS)."""
    return sig[params.n + (params.a + 1) * params.k * params.n :]


def spx_keygen(params: Parameters):
    """Generate a fresh SPHINCS+ key pair.

    Draws three ``n``-byte seeds (``sk_seed``, ``sk_prf``, ``pk_seed``) from
    :mod:`secrets` and computes the top-layer XMSS root that binds them.
    When ``OPTIMISED`` is ``True`` the root derivation runs under an active
    ``HashCtx`` so every inner hash takes the pre-absorbed fast path.

    Args:
        params: Parameter set (hash, dimensions, randomisation flag).

    Returns:
        ``(sk, pk)`` where ``sk = (sk_seed, sk_prf, pk_seed, pk_root)`` and
        ``pk = (pk_seed, pk_root)``.
    """
    sk_seed = secrets.token_bytes(params.n)
    sk_prf = secrets.token_bytes(params.n)
    pk_seed = secrets.token_bytes(params.n)
    if OPTIMISED:
        set_hash_ctx(HashCtx(pk_seed, params, sk_seed=sk_seed))
        try:
            pk_root = hypertree_gen_pk(sk_seed, pk_seed, params)
        finally:
            clear_hash_ctx()
    else:
        pk_root = hypertree_gen_pk(sk_seed, pk_seed, params)
    return ((sk_seed, sk_prf, pk_seed, pk_root), (pk_seed, pk_root))


def spx_sign(
    msg: bytes, sk: tuple[bytes, bytes, bytes, bytes], params: Parameters
) -> bytes:
    """Produce a SPHINCS+ signature over ``msg`` under secret key ``sk``.

    Installs a ``HashCtx`` with both ``pk_seed`` and ``sk_seed`` pre-absorbed
    when ``OPTIMISED`` is ``True`` (so ``h``, ``prf`` and any ``h_adrs_bytes``
    calls under :mod:`src.xmss` take the fast path), then delegates to
    :func:`_spx_sign_body`. The context is torn down on exit so later calls
    from other threads/paths are unaffected.

    Args:
        msg: Message bytes.
        sk: ``(sk_seed, sk_prf, pk_seed, pk_root)`` as returned by ``spx_keygen``.
        params: Parameter set.

    Returns:
        The concatenated signature ``R || sig_fors || sig_ht``.
    """
    sk_seed, sk_prf, pk_seed, pk_root = sk
    if OPTIMISED:
        set_hash_ctx(HashCtx(pk_seed, params, sk_seed=sk_seed))
        try:
            return _spx_sign_body(msg, sk, params)
        finally:
            clear_hash_ctx()
    return _spx_sign_body(msg, sk, params)


def _spx_sign_body(
    msg: bytes, sk: tuple[bytes, bytes, bytes, bytes], params: Parameters
) -> bytes:
    """Inner body of :func:`spx_sign` independent of the ``HashCtx`` machinery.

    Runs regardless of the optimisation flag. Computes the per-signature
    randomiser ``R = PRF_msg(sk_prf, opt, msg)``, expands it through ``H_msg``
    into a ``k * log_t``-bit FORS digest plus the two hypertree index slices,
    invokes ``fors_sign`` on the indicated (tree, leaf) and finally signs the
    FORS root with ``hypertree_sign``.

    Args:
        msg: Message bytes.
        sk: ``(sk_seed, sk_prf, pk_seed, pk_root)`` tuple.
        params: Parameter set.

    Returns:
        The concatenated signature ``R || sig_fors || sig_ht``.
    """
    sk_seed, sk_prf, pk_seed, pk_root = sk
    adrs = ADRS()

    opt = pk_seed
    if params.RANDOMIZE:
        opt = secrets.token_bytes(params.n)

    R = prf_msg(sk_prf, opt, msg, params)
    sig = R

    msg_digest = h_msg(R, pk_seed, pk_root, msg, params)
    tmp_md = msg_digest[: params.len_md()]
    tmp_idx_tree = msg_digest[params.len_md() : params.len_md() + params.idx_tree_len()]
    tmp_idx_leaf = msg_digest[params.len_md() + params.idx_tree_len() :]

    md = get_md(tmp_md, params)
    md_bytes = md.to_bytes((params.k * params.log_t + 7) // 8, byteorder="big")
    idx_tree = get_idx_tree(tmp_idx_tree, params)
    idx_leaf = get_idx_leaf(tmp_idx_leaf, params)

    adrs.set_layer(0)
    adrs.set_tree(idx_tree)
    adrs.set_type(AdrsType.FORS_TREE)
    adrs.set_key_pair(idx_leaf)

    sig_fors = fors_sign(md_bytes, sk_seed, pk_seed, adrs, params)
    sig += sig_fors

    pk_fors = fors_pk_from_sig(sig_fors, md_bytes, pk_seed, adrs, params)
    adrs.set_type(AdrsType.TREE)
    sig_ht = hypertree_sign(pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf, params)
    sig += sig_ht
    return sig


def spx_verify(
    msg: bytes, sig: bytes, pk: tuple[bytes, bytes], params: Parameters
) -> bool:
    """Verify a SPHINCS+ signature.

    Mirrors :func:`spx_sign`: installs a ``HashCtx`` with ``pk_seed``
    pre-absorbed (no ``sk_seed`` — verification never needs ``prf``) when
    ``OPTIMISED`` is ``True`` and delegates to :func:`_spx_verify_body`.

    Args:
        msg: Message the signature is allegedly over.
        sig: The signature bytes produced by :func:`spx_sign`.
        pk: ``(pk_seed, pk_root)`` as returned by ``spx_keygen``.
        params: Parameter set; must match the signer's.

    Returns:
        ``True`` iff the reconstructed hypertree root equals ``pk_root``.
    """
    pk_seed, pk_root = pk
    if OPTIMISED:
        set_hash_ctx(HashCtx(pk_seed, params))
        try:
            return _spx_verify_body(msg, sig, pk, params)
        finally:
            clear_hash_ctx()
    return _spx_verify_body(msg, sig, pk, params)


def _spx_verify_body(
    msg: bytes, sig: bytes, pk: tuple[bytes, bytes], params: Parameters
) -> bool:
    """Inner body of :func:`spx_verify`; slices the signature, reconstructs the
    FORS public key via ``fors_pk_from_sig`` and delegates the Merkle chain to
    ``hypertree_verify``.

    Args:
        msg: Message the signature is allegedly over.
        sig: The signature bytes to verify.
        pk: ``(pk_seed, pk_root)`` tuple.
        params: Parameter set.

    Returns:
        ``True`` iff the signature is valid under ``pk``.
    """
    pk_seed, pk_root = pk
    adrs = ADRS()
    r = get_r_from_sig(sig, params)
    sig_fors = get_sig_fors_from_sig(sig, params)
    sig_ht = get_sig_ht_from_sig(sig, params)

    msg_digest = h_msg(r, pk_seed, pk_root, msg, params)
    tmp_md = msg_digest[: params.len_md()]
    tmp_idx_tree = msg_digest[params.len_md() : params.len_md() + params.idx_tree_len()]
    tmp_idx_leaf = msg_digest[params.len_md() + params.idx_tree_len() :]

    md = get_md(tmp_md, params)
    md_bytes = md.to_bytes((params.k * params.log_t + 7) // 8, byteorder="big")
    idx_tree = get_idx_tree(tmp_idx_tree, params)
    idx_leaf = get_idx_leaf(tmp_idx_leaf, params)

    adrs.set_layer(0)
    adrs.set_tree(idx_tree)
    adrs.set_type(AdrsType.FORS_TREE)
    adrs.set_key_pair(idx_leaf)

    pk_fors = fors_pk_from_sig(sig_fors, md_bytes, pk_seed, adrs, params)
    adrs.set_type(AdrsType.TREE)
    return hypertree_verify(
        pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root, params
    )
