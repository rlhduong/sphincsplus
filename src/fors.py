"""FORS — Forest Of Random Subsets.

FORS is the few-times signature layer sitting at the bottom of a SPHINCS+
signature. A FORS key consists of ``k`` independent binary Merkle trees of
height ``a``; a signature over an ``(a * k)``-bit digest reveals one leaf
per tree plus the associated authentication path. The resulting FORS public
key (the hash of all ``k`` roots) is what the hypertree above actually
signs.
"""

from src.address import ADRS, AdrsType
from src.parameters import Parameters
from src.hash import h, prf


def get_idx_from_msg(msg_digest: bytes, i: int, params: Parameters) -> int:
    """Extract the ``i``-th FORS leaf index from the message digest.

    ``msg_digest`` is treated as a big-endian integer split into ``k`` groups
    of ``a`` bits (MSB-first); this function returns the ``i``-th group.

    Args:
        msg_digest: The ``len_md``-byte FORS digest slice of ``H_msg``.
        i: FORS tree index in ``[0, params.k)``.
        params: Parameter set (``params.a`` = tree height).

    Returns:
        An integer in ``[0, 2**a)`` naming the revealed leaf of tree ``i``.
    """
    bits = len(msg_digest) * 8
    value = int.from_bytes(msg_digest, byteorder="big")

    idx = (value >> (bits - (i + 1) * params.a)) & ((1 << params.a) - 1)
    return idx


def get_sk_from_sig(sig_fors: bytes, i: int, params: Parameters) -> bytes:
    """Return the ``n``-byte secret leaf of FORS tree ``i`` from the FORS signature.

    A FORS signature lays out ``k`` blocks of ``n + a * n`` bytes: one secret
    leaf followed by its ``a``-node authentication path.
    """
    sk_len = params.n
    return sig_fors[
        i * (sk_len + params.a * params.n) : i * (sk_len + params.a * params.n) + sk_len
    ]


def get_auth_path_from_sig(sig_fors: bytes, i: int, params: Parameters) -> list[bytes]:
    """Return the ``a``-node authentication path for FORS tree ``i`` as a list of ``n``-byte nodes."""
    auth_path = []
    for j in range(0, params.a):
        start = i * (params.n + params.a * params.n) + params.n + j * params.n
        end = start + params.n
        auth_path.append(sig_fors[start:end])
    return auth_path


def fors_sk_gen(sk_seed: bytes, adrs: ADRS, idx: int, params: Parameters) -> bytes:
    """Derive the FORS secret leaf at absolute index ``idx``.

    Switches ``adrs`` onto the ``FORS_PRF`` type (carrying the caller's
    ``key_pair`` forward) and calls ``prf(sk_seed, adrs, params)``. ``idx``
    spans every leaf across every FORS tree (``0 <= idx < k * 2**a``).

    Args:
        sk_seed: Secret seed.
        adrs: Base address; ``key_pair`` selects the FORS instance.
        idx: Absolute leaf index inside the combined FORS forest.
        params: Parameter set.

    Returns:
        ``n``-byte FORS leaf secret.
    """
    sk_adrs = adrs.copy()
    sk_adrs.set_type(AdrsType.FORS_PRF)
    sk_adrs.set_key_pair(adrs.get_key_pair())

    sk_adrs.set_tree_height(0)
    sk_adrs.set_tree_index(idx)
    sk = prf(sk_seed, sk_adrs, params)
    return sk


def fors_treehash(
    sk_seed: bytes, s: int, z: int, pk_seed: bytes, adrs: ADRS, params: Parameters
) -> bytes:
    """Compute a FORS sub-tree root by streaming leaves into a stack.

    Hashes ``2**z`` consecutive FORS leaves starting at absolute index ``s``
    and folds them pairwise up to the root using the ``FORS_TREE`` address
    type. ``s`` must be a multiple of ``2**z`` (required for the stack-based
    algorithm to land on a well-aligned sub-tree).

    Args:
        sk_seed: Secret seed used to derive leaf secrets via ``fors_sk_gen``.
        s: Starting leaf index.
        z: Sub-tree height (``0 <= z <= a``).
        pk_seed: Public seed feeding the tweakable hash.
        adrs: Base address; its ``key_pair`` field identifies the FORS instance.
        params: Parameter set.

    Returns:
        The ``n``-byte root of the requested sub-tree, or ``-1`` if ``s`` is
        misaligned (matching the reference implementation's behaviour).
    """
    if s % (1 << z) != 0:
        return -1

    stack = []

    for i in range(0, 1 << z):
        sk = fors_sk_gen(sk_seed, adrs, s + i, params)
        # Set the FORS leaf address (tree_height=0, tree_index=s+i) before
        # hashing so that it matches the leaf-hash input that
        # `fors_pk_from_sig` constructs during verification. Without this,
        # fors_pk_gen and fors_pk_from_sig disagree as soon as
        # `ADRS.to_bytes()` faithfully emits the tree_height/tree_index slots.
        adrs.set_tree_height(0)
        adrs.set_tree_index(s + i)
        node = h(pk_seed, adrs.copy(), sk, params)

        adrs.set_tree_height(1)
        adrs.set_tree_index(s + i)

        while len(stack) > 0 and stack[-1][1] == adrs.get_tree_height():
            adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
            node = h(pk_seed, adrs.copy(), stack.pop()[0] + node, params)
            adrs.set_tree_height(adrs.get_tree_height() + 1)

        stack.append((node, adrs.get_tree_height()))

    return stack[-1][0]


def fors_pk_gen(
    sk_seed: bytes, pk_seed: bytes, adrs: ADRS, params: Parameters
) -> bytes:
    """Compute the FORS public key: ``H(pk_seed, FORS_ROOTS, root_0 || ... || root_{k-1})``.

    Builds each of the ``k`` sub-tree roots with ``fors_treehash`` and hashes
    them together under a ``FORS_ROOTS``-typed address carrying the same
    ``key_pair`` as ``adrs``.

    Args:
        sk_seed: Secret seed.
        pk_seed: Public seed.
        adrs: Base address identifying the FORS instance (``key_pair`` set).
        params: Parameter set (``k`` trees, each of height ``a``).

    Returns:
        ``n``-byte FORS public key.
    """
    t = 1 << params.a
    fors_pk_adrs = adrs.copy()
    root = b""

    for i in range(0, params.k):
        root += fors_treehash(sk_seed, i * t, params.a, pk_seed, adrs.copy(), params)

    fors_pk_adrs.set_type(AdrsType.FORS_ROOTS)
    fors_pk_adrs.set_key_pair(adrs.get_key_pair())

    pk = h(pk_seed, fors_pk_adrs, root, params)
    return pk


def fors_sign(
    msg_digest: bytes, sk_seed: bytes, pk_seed: bytes, adrs: ADRS, params: Parameters
) -> bytes:
    """Produce a FORS signature over ``msg_digest``.

    For each of the ``k`` FORS trees, extracts the ``a``-bit leaf index via
    ``get_idx_from_msg``, reveals the corresponding leaf secret and emits the
    authentication path by repeatedly invoking ``fors_treehash`` on the
    appropriate sibling sub-trees.

    ``msg_digest`` is exactly ``floor((k * log_t + 7) / 8)`` bytes — the
    ``len_md`` slice carved from the output of ``H_msg``.

    Args:
        msg_digest: FORS message-digest slice.
        sk_seed: Secret seed.
        pk_seed: Public seed.
        adrs: Base address (FORS instance selected via ``key_pair``).
        params: Parameter set.

    Returns:
        ``(a + 1) * k * n`` bytes of FORS signature.
    """
    t = 1 << params.a
    sig_fors = b""

    for i in range(0, params.k):
        idx = get_idx_from_msg(msg_digest, i, params)

        sig_fors += fors_sk_gen(sk_seed, adrs, i * t + idx, params)

        auth_path = b""
        for j in range(0, params.a):
            s = (idx // (1 << j)) ^ 1
            auth_path += fors_treehash(
                sk_seed, i * t + s * (1 << j), j, pk_seed, adrs.copy(), params
            )

        sig_fors += auth_path
    return sig_fors


def fors_pk_from_sig(
    sig_fors: bytes, msg_digest: bytes, pk_seed: bytes, adrs: ADRS, params: Parameters
) -> bytes:
    """Reconstruct the FORS public key from a FORS signature during verification.

    For each of the ``k`` trees the function extracts the revealed leaf and
    authentication path from ``sig_fors``, hashes the leaf at height 0 and
    walks the auth path up to the root. All ``k`` roots are concatenated and
    hashed under a ``FORS_ROOTS`` address, matching what ``fors_pk_gen``
    produces. If the signature is valid, the returned key equals the original.

    Args:
        sig_fors: The ``(a + 1) * k * n``-byte FORS signature.
        msg_digest: FORS message-digest slice (same as passed to ``fors_sign``).
        pk_seed: Public seed.
        adrs: Base address (FORS instance selected via ``key_pair``).
        params: Parameter set.

    Returns:
        ``n``-byte reconstructed FORS public key.
    """
    t = 1 << params.a
    root = b""
    node_0 = b""
    node_1 = node_0

    for i in range(0, params.k):
        idx = get_idx_from_msg(msg_digest, i, params)

        sk = get_sk_from_sig(sig_fors, i, params)
        adrs.set_tree_height(0)
        adrs.set_tree_index(i * t + idx)
        node_0 = h(pk_seed, adrs.copy(), sk, params)

        auth_path = get_auth_path_from_sig(sig_fors, i, params)
        adrs.set_tree_index(i * t + idx)

        for j in range(0, params.a):
            adrs.set_tree_height(j + 1)
            if (idx // (1 << j)) % 2 == 0:
                adrs.set_tree_index(adrs.get_tree_index() // 2)
                node_1 = h(pk_seed, adrs.copy(), node_0 + auth_path[j], params)
            else:
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node_1 = h(pk_seed, adrs.copy(), auth_path[j] + node_0, params)
            node_0 = node_1
        root += node_0

    fors_pk_adrs = adrs.copy()
    fors_pk_adrs.set_type(AdrsType.FORS_ROOTS)
    fors_pk_adrs.set_key_pair(adrs.get_key_pair())
    pk = h(pk_seed, fors_pk_adrs, root, params)
    return pk
