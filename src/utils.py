"""Byte / bit / base-w helpers used throughout SPHINCS+.

These are the small, stateless conversions described in Section 2 of the
SPHINCS+ specification (eprint 2019/1086): big-endian integer <-> byte
conversions, splitting a serialised signature into fixed-size chunks, and the
`base_w` routine that re-expresses a byte string as a sequence of base-w
digits for WOTS+.
"""

import math


def to_bytes(x: int, length: int) -> bytes:
    """Encode a non-negative integer as a big-endian byte string of ``length`` bytes."""
    return x.to_bytes(length, byteorder="big")


def from_bytes(b: bytes) -> int:
    """Decode a big-endian byte string into a non-negative integer."""
    return int.from_bytes(b, byteorder="big")


def sig_to_array(sig: bytes, n: int) -> list[bytes]:
    """Split a concatenated WOTS+ signature into ``wots_len`` chunks of ``n`` bytes each."""
    return [sig[i : i + n] for i in range(0, len(sig), n)]


def auth_path_to_array(auth_path: bytes, n: int) -> list[bytes]:
    """Split a serialised Merkle authentication path into individual ``n``-byte nodes."""
    return [auth_path[i : i + n] for i in range(0, len(auth_path), n)]


def first_bits(x: bytes, num_bits: int) -> int:
    """Return the most-significant ``num_bits`` of ``x`` as an integer.

    Used to extract FORS message-digest bits, tree index, and leaf index from
    the output of ``H_msg`` in ``spx_sign`` / ``spx_verify``.
    """
    bits = len(x) * 8
    value = int.from_bytes(x, byteorder="big")
    result = value >> (bits - num_bits)
    return result


def base_w(x: bytes, w: int, out_len: int) -> list[int]:
    """Convert a byte string into ``out_len`` base-``w`` digits (MSB-first).

    This is the routine WOTS+ uses to map a message digest to a chain-length
    vector. ``w`` must be a power of two; each output digit consumes
    ``log2(w)`` bits from ``x``, left-to-right. Consumes
    ``ceil(out_len * log2(w) / 8)`` bytes of input.
    """
    base_w_digits = []
    mask = w - 1
    log_w = int(math.log2(w))
    current_byte = 0
    bits = 0
    vin = 0

    for _ in range(out_len):
        if bits == 0:
            current_byte = x[vin]
            vin += 1
            bits += 8

        bits -= log_w
        base_w_digits.append((current_byte >> bits) & mask)

    return base_w_digits
