"""WOTS+ one-time signature scheme.

WOTS+ maps an ``n``-byte message digest to a vector of ``len1`` base-``w``
digits, appends a ``len2``-digit checksum, and advances each chain from its
secret starting value by the digit count. The public key is the hash of all
``wots_len`` chains at their maximum position (``w - 1``). Verification
recomputes the remaining chain steps from the signature to recover the same
public key.
"""

from src.address import ADRS, AdrsType
from src.parameters import Parameters
from src.utils import base_w, sig_to_array
import math
from src.hash import h, prf


def chain(
    x: bytes, i: int, s: int, pk_seed: bytes, adrs: ADRS, params: Parameters
) -> bytes:
    """Iterate the WOTS+ chain function ``s`` times starting at position ``i``.

    Applies ``H(pk_seed, ADRS, x)`` in a loop, advancing the ``hash`` field
    of ``adrs`` from ``i`` to ``i + s - 1``. Returns ``None`` (matching the
    reference spec) if ``i + s`` exceeds the Winternitz parameter ``w``.

    Args:
        x: Starting ``n``-byte chain value.
        i: Hash-step position to begin at (0-based).
        s: Number of hash iterations to apply.
        pk_seed: Public seed feeding the tweakable hash.
        adrs: Address with ``chain`` already set; ``hash`` is mutated in place.
        params: Parameter set (``w`` = chain length bound).

    Returns:
        ``n``-byte chain value after ``s`` iterations, or ``None`` if out of range.
    """
    if i + s > params.w:
        return None

    for k in range(s):
        adrs.set_hash(i + k)
        x = h(pk_seed, adrs, x, params)
    return x


def wots_gen_sk(sk_seed: bytes, adrs: ADRS, params: Parameters) -> list[bytes]:
    """Generate the ``wots_len``-element WOTS+ secret key as a list of ``n``-byte PRF outputs.

    Each element ``sk[i]`` is derived deterministically via
    ``prf(sk_seed, sk_adrs)`` with a ``WOTS_PRF``-typed address carrying
    ``(key_pair, chain=i, hash=0)``.

    Args:
        sk_seed: Secret seed.
        adrs: Base address; ``key_pair`` selects the WOTS+ instance.
        params: Parameter set.

    Returns:
        List of ``wots_len`` secret ``n``-byte chain starting values.
    """
    sk_adrs = adrs.copy()
    sk_adrs.set_type(AdrsType.WOTS_PRF)
    sk_adrs.set_key_pair(adrs.get_key_pair())
    sk = []

    for i in range(0, params.wots_len):
        sk_adrs.set_chain(i)
        sk_adrs.set_hash(0)
        sk.append(prf(sk_seed, sk_adrs, params))

    return sk


def wots_gen_pk(
    sk_seed: bytes, pk_seed: bytes, adrs: ADRS, params: Parameters
) -> bytes:
    """Generate the WOTS+ public key for the instance identified by ``adrs``.

    Derives the secret key via ``prf`` and chains each element ``w - 1`` steps
    to obtain the full-length chain endpoints. These are concatenated and
    hashed under a ``WOTS_PK``-typed address to produce a single ``n``-byte
    public key.

    Args:
        sk_seed: Secret seed.
        pk_seed: Public seed feeding the tweakable hash.
        adrs: Base address (``key_pair`` selects the instance).
        params: Parameter set.

    Returns:
        ``n``-byte WOTS+ compressed public key.
    """
    pk_adrs = adrs.copy()
    sk_adrs = adrs.copy()
    sk_adrs.set_type(AdrsType.WOTS_PRF)
    sk_adrs.set_key_pair(adrs.get_key_pair())

    tmp = b""
    sk = []

    for i in range(0, params.wots_len):
        sk_adrs.set_chain(i)
        sk_adrs.set_hash(0)
        sk.append(prf(sk_seed, sk_adrs, params))

        adrs.set_chain(i)
        adrs.set_hash(0)
        tmp += chain(sk[i], 0, params.w - 1, pk_seed, adrs, params)

    pk_adrs.set_type(AdrsType.WOTS_PK)
    pk_adrs.set_key_pair(adrs.get_key_pair())
    pk = h(pk_seed, pk_adrs, tmp, params)

    return pk


def wots_sign(
    msg_digest: bytes, sk_seed: bytes, pk_seed: bytes, adrs: ADRS, params: Parameters
) -> bytes:
    """Sign ``msg_digest`` with the WOTS+ instance at ``adrs``.

    Converts the ``n``-byte digest into ``len1`` base-``w`` digits, computes
    the ``len2``-digit checksum, and chains each secret-key element by the
    corresponding digit count. The resulting ``wots_len * n`` bytes form the
    signature.

    Args:
        msg_digest: ``n``-byte digest to sign.
        sk_seed: Secret seed (used to derive per-chain secrets via ``prf``).
        pk_seed: Public seed feeding the chain hash.
        adrs: Base address (``key_pair`` selects the instance).
        params: Parameter set.

    Returns:
        ``wots_len * n`` bytes of WOTS+ signature.
    """
    csum = 0

    msg_base_w = base_w(msg_digest, params.w, params.len1)

    for i in range(0, params.len1):
        csum += params.w - 1 - msg_base_w[i]

    pad = (8 - ((params.len2 * params.log_w) % 8)) % 8
    csum <<= pad

    csum_bytes = csum.to_bytes(
        math.ceil((params.len2 * params.log_w) / 8), byteorder="big"
    )
    csum_base_w = base_w(csum_bytes, params.w, params.len2)
    msg_base_w += csum_base_w

    sk_adrs = adrs.copy()
    sk_adrs.set_type(AdrsType.WOTS_PRF)
    sk_adrs.set_key_pair(adrs.get_key_pair())
    sig = b""
    for i in range(0, params.wots_len):
        sk_adrs.set_chain(i)
        sk_adrs.set_hash(0)
        sk = prf(sk_seed, sk_adrs, params)

        adrs.set_chain(i)
        adrs.set_hash(0)
        sig += chain(sk, 0, msg_base_w[i], pk_seed, adrs, params)

    return sig


def wots_pk_from_sig(
    sig: bytes, msg_digest: bytes, pk_seed: bytes, adrs: ADRS, params: Parameters
) -> bytes:
    """Reconstruct the WOTS+ public key from a signature during verification.

    Re-derives the base-``w`` digit vector (message + checksum) and chains
    each signature element from position ``digit[i]`` up to ``w - 1``. If the
    signature is valid, the resulting chain endpoints match ``wots_gen_pk``
    and the compressed hash equals the original public key.

    Args:
        sig: ``wots_len * n``-byte WOTS+ signature.
        msg_digest: ``n``-byte digest the signature is allegedly over.
        pk_seed: Public seed feeding the chain hash.
        adrs: Base address (``key_pair`` selects the instance).
        params: Parameter set.

    Returns:
        ``n``-byte reconstructed WOTS+ public key.
    """
    csum = 0

    msg_base_w = base_w(msg_digest, params.w, params.len1)

    for i in range(0, params.len1):
        csum += params.w - 1 - msg_base_w[i]

    pad = (8 - ((params.len2 * params.log_w) % 8)) % 8
    csum <<= pad

    csum_bytes = csum.to_bytes(
        math.ceil((params.len2 * params.log_w) / 8), byteorder="big"
    )
    csum_base_w = base_w(csum_bytes, params.w, params.len2)
    msg_base_w += csum_base_w

    sig_array = sig_to_array(sig, params.n)
    tmp = b""
    for i in range(0, params.wots_len):
        adrs.set_chain(i)
        adrs.set_hash(0)
        tmp += chain(
            sig_array[i],
            msg_base_w[i],
            params.w - 1 - msg_base_w[i],
            pk_seed,
            adrs,
            params,
        )

    pk_adrs = adrs.copy()
    pk_adrs.set_type(AdrsType.WOTS_PK)
    pk_adrs.set_key_pair(adrs.get_key_pair())
    return h(pk_seed, pk_adrs, tmp, params)
