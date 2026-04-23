"""XMSS — eXtended Merkle Signature Scheme.

Each XMSS tree is a single layer of the SPHINCS+ hypertree. It combines
``2**h_prime`` WOTS+ key pairs as leaves and connects them through a binary
Merkle tree of height ``h_prime``. The root of the tree serves as the public
key for that layer.

The module-level ``ADRS_SNAPSHOT`` flag (Optimisation 4) controls whether
inner-node hashes use ``h_adrs_bytes`` (which skips the ``ADRS.copy()``
allocation) or the baseline ``h(pk_seed, adrs.copy(), …)`` path.
"""

import math
from src.address import ADRS, AdrsType
from src.parameters import Parameters
from src.wots import wots_gen_pk, wots_sign, wots_pk_from_sig
from src.utils import auth_path_to_array
from src.hash import h, h_adrs_bytes


# Optimisation 4 toggle — set to False to revert to adrs.copy() for benchmarking.
ADRS_SNAPSHOT: bool = True


def treehash(
    sk_seed: bytes, s: int, z: int, pk_seed: bytes, adrs: ADRS, params: Parameters
) -> bytes:
    """Compute the root of an XMSS sub-tree of height ``z`` starting at leaf ``s``.

    Generates ``2**z`` consecutive WOTS+ public keys (one per leaf), then
    folds them pairwise through a stack-based Merkle construction using
    ``TREE``-typed addresses. ``s`` must be aligned to ``2**z``.

    When ``ADRS_SNAPSHOT`` is ``True`` the inner-node hash takes the
    ``h_adrs_bytes`` fast path that avoids an ``ADRS`` object copy per node.

    Args:
        sk_seed: Secret seed.
        s: Starting leaf index (must be a multiple of ``2**z``).
        z: Sub-tree height.
        pk_seed: Public seed.
        adrs: Base address; ``layer`` and ``tree`` must already be set.
        params: Parameter set.

    Returns:
        ``n``-byte sub-tree root, or ``-1`` if ``s`` is misaligned.
    """
    if s % (1 << z) != 0:
        return -1

    stack = []
    for i in range(0, 1 << z):
        adrs.set_type(AdrsType.WOTS_HASH)
        adrs.set_key_pair(s + i)
        node = wots_gen_pk(sk_seed, pk_seed, adrs, params)

        adrs.set_type(AdrsType.TREE)
        adrs.set_tree_height(1)
        adrs.set_tree_index(s + i)

        while len(stack) > 0 and stack[-1][1] == adrs.get_tree_height():
            adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
            # Opt-4: snapshot ADRS bytes once — avoids allocating a full ADRS
            # object + bytearray(32) copy just so h() can call to_bytes() on it.
            node = (
                h_adrs_bytes(pk_seed, adrs.to_bytes(), stack.pop()[0] + node, params)
                if ADRS_SNAPSHOT
                else h(pk_seed, adrs.copy(), stack.pop()[0] + node, params)
            )
            adrs.set_tree_height(adrs.get_tree_height() + 1)

        stack.append((node, adrs.get_tree_height()))

    return stack[-1][0]


def xmss_pk_gen(
    sk_seed: bytes, pk_seed: bytes, adrs: ADRS, params: Parameters
) -> bytes:
    """Generate the XMSS public key (tree root) by calling ``treehash`` over all ``2**h_prime`` leaves.

    Args:
        sk_seed: Secret seed.
        pk_seed: Public seed.
        adrs: Base address with ``layer`` and ``tree`` set.
        params: Parameter set (``h_prime`` = single-layer tree height).

    Returns:
        ``n``-byte XMSS tree root.
    """
    return treehash(sk_seed, 0, params.h_prime, pk_seed, adrs, params)


def xmss_sign(
    msg_digest: bytes,
    sk_seed: bytes,
    idx: int,
    pk_seed: bytes,
    adrs: ADRS,
    params: Parameters,
) -> bytes:
    """Produce an XMSS signature using leaf ``idx``.

    Computes the ``h_prime``-node authentication path by calling ``treehash``
    on each sibling sub-tree, then signs ``msg_digest`` with the WOTS+ key
    pair at position ``idx``. The output concatenates
    ``wots_sig || auth_path``.

    Args:
        msg_digest: ``n``-byte digest to sign (FORS root or upper-layer root).
        sk_seed: Secret seed.
        idx: Leaf index within this XMSS tree (``0 <= idx < 2**h_prime``).
        pk_seed: Public seed.
        adrs: Base address with ``layer`` and ``tree`` set.
        params: Parameter set.

    Returns:
        ``(wots_len + h_prime) * n`` bytes of XMSS signature.
    """
    auth_path = b""
    for j in range(0, params.h_prime):
        k = math.floor(idx / (1 << j)) ^ 1
        auth_path += treehash(sk_seed, k * (1 << j), j, pk_seed, adrs, params)

    adrs.set_type(AdrsType.WOTS_HASH)
    adrs.set_key_pair(idx)
    sig = wots_sign(msg_digest, sk_seed, pk_seed, adrs.copy(), params)
    sig_xmss = sig + auth_path
    return sig_xmss


def xmss_pk_from_sig(
    idx: int,
    sig_xmss: bytes,
    msg_digest: bytes,
    pk_seed: bytes,
    adrs: ADRS,
    params: Parameters,
) -> bytes:
    """Reconstruct the XMSS tree root from an XMSS signature.

    Recovers the WOTS+ public key at leaf ``idx`` via ``wots_pk_from_sig``,
    then walks the authentication path from the leaf up to the root using
    ``TREE``-typed addresses. If the signature is valid, the returned root
    equals the output of ``xmss_pk_gen``.

    Args:
        idx: Leaf index that was used when signing.
        sig_xmss: ``(wots_len + h_prime) * n``-byte XMSS signature.
        msg_digest: ``n``-byte digest the signature is over.
        pk_seed: Public seed.
        adrs: Base address with ``layer`` and ``tree`` set.
        params: Parameter set.

    Returns:
        ``n``-byte reconstructed XMSS tree root.
    """
    adrs.set_type(AdrsType.WOTS_HASH)
    adrs.set_key_pair(idx)
    sig = sig_xmss[: (params.wots_len * params.n)]
    auth_path_bytes = sig_xmss[(params.wots_len * params.n) :]
    auth_path = auth_path_to_array(auth_path_bytes, params.n)

    node_0 = wots_pk_from_sig(sig, msg_digest, pk_seed, adrs.copy(), params)
    node_1 = node_0

    adrs.set_type(AdrsType.TREE)
    adrs.set_tree_index(idx)

    for k in range(0, params.h_prime):
        adrs.set_tree_height(k + 1)
        if (idx // (1 << k)) % 2 == 0:
            adrs.set_tree_index(adrs.get_tree_index() // 2)
            # Opt-4: snapshot bytes instead of cloning the ADRS object.
            node_1 = (
                h_adrs_bytes(pk_seed, adrs.to_bytes(), node_0 + auth_path[k], params)
                if ADRS_SNAPSHOT
                else h(pk_seed, adrs.copy(), node_0 + auth_path[k], params)
            )
        else:
            adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
            node_1 = (
                h_adrs_bytes(pk_seed, adrs.to_bytes(), auth_path[k] + node_0, params)
                if ADRS_SNAPSHOT
                else h(pk_seed, adrs.copy(), auth_path[k] + node_0, params)
            )
        node_0 = node_1

    return node_0
