"""SPHINCS+ ADRS (32-byte hash-tweak address) implementation.

Layout of the serialised 32-byte address:

    [0:4]   layer
    [4:16]  tree
    [16:20] type
    [20:24] WORD1  (key_pair in most types)
    [24:28] WORD2  (chain / tree_height, depending on type)
    [28:32] WORD3  (hash / tree_index, depending on type)

This module maintains the serialised form as a single persistent
`bytearray(32)` and mutates it in place through `struct.pack_into`. This is a
performance optimisation: inside a single `spx_sign` call on
`sphincs-sha2-128s`, `to_bytes()` is called ~2.2 million times - re-allocating
a fresh buffer and re-copying every field each time dominated the baseline
profile (~28% of total sign time). Mutating in place and returning
`bytes(self._buf)` makes `to_bytes()` a single memcpy.

The public API (`set_layer`, `set_tree`, `set_type`, `set_key_pair`,
`set_chain`, `set_hash`, `set_tree_index`, `set_tree_height`, `copy`,
`to_bytes`, getters) is unchanged, so every call site continues to work
without modification.
"""

import struct
from enum import IntEnum


class AdrsType(IntEnum):
    """SPHINCS+ ADRS ``type`` field values (written into bytes ``[16:20]``).

    ``WOTS_HASH`` / ``WOTS_PK`` / ``WOTS_PRF`` are used during WOTS+ chain
    construction and public-key hashing. ``TREE`` addresses inner nodes of
    an XMSS tree. ``FORS_TREE`` / ``FORS_ROOTS`` / ``FORS_PRF`` cover the
    analogous roles inside the FORS sub-signature.
    """

    WOTS_HASH = 0
    WOTS_PK = 1
    TREE = 2
    FORS_TREE = 3
    FORS_ROOTS = 4
    WOTS_PRF = 5
    FORS_PRF = 6


class ADRS:
    """Mutable SPHINCS+ address with in-place field updates.

    A single ``bytearray(32)`` backs every field; setters use
    ``struct.pack_into`` so switching fields never reallocates. The
    ``type`` attribute is mirrored on the Python object for fast access
    without having to unpack the serialised ``[16:20]`` slice.
    """

    __slots__ = ("_buf", "type")

    def __init__(self):
        """Create a zeroed address with ``type = AdrsType.WOTS_HASH`` (value 0)."""
        self._buf = bytearray(32)
        self.type = AdrsType(0)

    def copy(self) -> "ADRS":
        """Return an independent copy that can be mutated without affecting ``self``.

        Used by hash call sites that need to freeze the address at a given
        moment while the caller keeps mutating the original during tree
        traversal. :func:`src.hash.h_adrs_bytes` lets most of these sites
        skip the copy entirely.
        """
        c = ADRS.__new__(ADRS)
        c._buf = bytearray(self._buf)
        c.type = self.type
        return c

    def to_bytes(self) -> bytes:
        """Return the 32-byte serialised form expected by ``h`` / ``prf``."""
        return bytes(self._buf)

    # --- setters ------------------------------------------------------------
    def set_layer(self, layer: int) -> None:
        """Write the hypertree layer index into ``[0:4]`` (big-endian uint32)."""
        struct.pack_into(">I", self._buf, 0, layer)

    def set_tree(self, tree: int) -> None:
        """Write the 64-bit tree index into the low 8 bytes of ``[4:16]``.

        The SPHINCS+ ADRS allocates 12 bytes (96 bits) for ``tree`` but the
        standard parameter sets never exceed 64 bits of tree index, so the
        high 4 bytes are always zero.
        """
        self._buf[4:8] = b"\x00\x00\x00\x00"
        struct.pack_into(">Q", self._buf, 8, tree)

    def set_type(self, type: "AdrsType") -> None:
        """Set the address ``type`` and clear WORD1/2/3.

        The spec mandates that changing the type zeros the per-type fields
        so stale ``chain``/``hash``/``tree_height``/``tree_index`` values from
        a previous type cannot leak into a new tweak input.
        """
        self.type = type
        struct.pack_into(">I", self._buf, 16, int(type))
        self._buf[20:32] = b"\x00" * 12

    def set_key_pair(self, key_pair: int) -> None:
        """Write the WOTS+/FORS key-pair index into ``[20:24]`` (WORD1)."""
        struct.pack_into(">I", self._buf, 20, key_pair)

    def set_chain(self, chain: int) -> None:
        """Write the WOTS+ chain index into ``[24:28]`` (WORD2)."""
        struct.pack_into(">I", self._buf, 24, chain)

    def set_hash(self, hash: int) -> None:
        """Write the WOTS+ chain step / hash index into ``[28:32]`` (WORD3)."""
        struct.pack_into(">I", self._buf, 28, hash)

    def set_tree_index(self, tree_index: int) -> None:
        """Write the Merkle-tree node index into ``[28:32]`` (WORD3, TREE/FORS types)."""
        struct.pack_into(">I", self._buf, 28, tree_index)

    def set_tree_height(self, tree_height: int) -> None:
        """Write the Merkle-tree node height into ``[24:28]`` (WORD2, TREE/FORS types)."""
        struct.pack_into(">I", self._buf, 24, tree_height)

    # --- getters ------------------------------------------------------------
    def get_key_pair(self) -> int:
        """Read WORD1 interpreted as the current key-pair index."""
        return struct.unpack_from(">I", self._buf, 20)[0]

    def get_tree_index(self) -> int:
        """Read WORD3 interpreted as the current tree-node index."""
        return struct.unpack_from(">I", self._buf, 28)[0]

    def get_tree_height(self) -> int:
        """Read WORD2 interpreted as the current tree-node height."""
        return struct.unpack_from(">I", self._buf, 24)[0]

    def __str__(self) -> str:
        return f"ADRS(type={self.type}, buf={bytes(self._buf).hex()})"

    def __repr__(self) -> str:
        return self.__str__()
