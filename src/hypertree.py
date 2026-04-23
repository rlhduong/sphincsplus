"""Hypertree — ``d``-layer tower of XMSS trees.

The hypertree stacks ``d`` XMSS trees on top of one another. The root of
layer ``j`` signs the root of layer ``j - 1``; the bottom layer (layer 0)
signs the FORS public key produced during ``spx_sign``. The root of the
top layer (layer ``d - 1``) is ``pk_root`` — the public key component that
binds the entire structure.
"""

from src.address import ADRS
from src.parameters import Parameters
from src.xmss import xmss_pk_gen, xmss_sign, xmss_pk_from_sig


def get_xmss_sig_by_level(sig_ht: bytes, level: int, params: Parameters) -> bytes:
    """Slice out the XMSS signature for layer ``level`` from the hypertree signature.

    Each per-layer XMSS signature occupies ``n * (wots_len + h_prime)`` bytes
    and they are concatenated in layer order (0, 1, …, d - 1).

    Args:
        sig_ht: Full hypertree signature.
        level: Layer index (``0 <= level < d``).
        params: Parameter set.

    Returns:
        ``(wots_len + h_prime) * n`` bytes of the layer-``level`` XMSS signature.
    """
    xmss_len = params.n * (params.wots_len + params.h_prime)
    return sig_ht[level * xmss_len : (level + 1) * xmss_len]


def hypertree_gen_pk(sk_seed: bytes, pk_seed: bytes, params: Parameters) -> bytes:
    """Generate the hypertree public key (top-layer XMSS root).

    Computes a single XMSS tree at the top layer (``d - 1``) with tree
    index 0. The returned root is ``pk_root``, the portion of the SPHINCS+
    public key that anchors verification.

    Args:
        sk_seed: Secret seed.
        pk_seed: Public seed.
        params: Parameter set.

    Returns:
        ``n``-byte hypertree root.
    """
    adrs = ADRS()
    adrs.set_layer(params.d - 1)
    adrs.set_tree(0)
    root = xmss_pk_gen(sk_seed, pk_seed, adrs, params)
    return root


def hypertree_sign(
    msg_digest: bytes,
    sk_seed: bytes,
    pk_seed: bytes,
    idx_tree: int,
    idx_leaf: int,
    params: Parameters,
) -> bytes:
    """Produce a hypertree signature over ``msg_digest``.

    Signs bottom-up through all ``d`` layers. At layer 0, the indicated
    (``idx_tree``, ``idx_leaf``) XMSS tree signs ``msg_digest`` (the FORS
    public key). Each subsequent layer signs the root of the layer below it.
    ``idx_tree`` is progressively right-shifted by ``h_prime`` bits to select
    the next tree index and leaf.

    Args:
        msg_digest: ``n``-byte value to sign (typically the FORS public key).
        sk_seed: Secret seed.
        pk_seed: Public seed.
        idx_tree: Tree index at the bottom layer.
        idx_leaf: Leaf index at the bottom layer.
        params: Parameter set.

    Returns:
        ``d * (wots_len + h_prime) * n`` bytes of hypertree signature.
    """
    adrs = ADRS()
    adrs.set_layer(0)
    adrs.set_tree(idx_tree)
    sig_tmp = xmss_sign(msg_digest, sk_seed, idx_leaf, pk_seed, adrs.copy(), params)

    sig_ht = sig_tmp
    root = xmss_pk_from_sig(idx_leaf, sig_tmp, msg_digest, pk_seed, adrs, params)

    for j in range(1, params.d):
        idx_leaf = idx_tree & ((1 << params.h_prime) - 1)
        idx_tree >>= params.h_prime

        adrs.set_layer(j)
        adrs.set_tree(idx_tree)
        sig_tmp = xmss_sign(root, sk_seed, idx_leaf, pk_seed, adrs, params)
        sig_ht += sig_tmp

        if j < params.d - 1:
            root = xmss_pk_from_sig(idx_leaf, sig_tmp, root, pk_seed, adrs, params)

    return sig_ht


def hypertree_verify(
    msg_digest: bytes,
    sig_ht: bytes,
    pk_seed: bytes,
    idx_tree: int,
    idx_leaf: int,
    pk_ht: bytes,
    params: Parameters,
) -> bool:
    """Verify a hypertree signature.

    Reconstructs the root layer-by-layer from the bottom up using
    ``xmss_pk_from_sig``. At each layer the recovered root becomes the
    message for the next layer's XMSS verification. The signature is valid
    iff the final recovered root equals ``pk_ht``.

    Args:
        msg_digest: ``n``-byte value that was signed (FORS public key).
        sig_ht: Full hypertree signature (``d`` concatenated XMSS sigs).
        pk_seed: Public seed.
        idx_tree: Tree index at the bottom layer.
        idx_leaf: Leaf index at the bottom layer.
        pk_ht: Expected hypertree root (from the public key).
        params: Parameter set.

    Returns:
        ``True`` iff the reconstructed root matches ``pk_ht``.
    """
    adrs = ADRS()
    adrs.set_layer(0)
    adrs.set_tree(idx_tree)

    sig_tmp = get_xmss_sig_by_level(sig_ht, 0, params)
    node = xmss_pk_from_sig(idx_leaf, sig_tmp, msg_digest, pk_seed, adrs, params)

    for j in range(1, params.d):
        idx_leaf = idx_tree & ((1 << params.h_prime) - 1)
        idx_tree >>= params.h_prime
        sig_tmp = get_xmss_sig_by_level(sig_ht, j, params)
        adrs.set_layer(j)
        adrs.set_tree(idx_tree)
        node = xmss_pk_from_sig(idx_leaf, sig_tmp, node, pk_seed, adrs, params)

    return node == pk_ht
