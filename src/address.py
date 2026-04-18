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
    WOTS_HASH  = 0
    WOTS_PK    = 1
    TREE       = 2
    FORS_TREE  = 3
    FORS_ROOTS = 4
    WOTS_PRF   = 5
    FORS_PRF   = 6


class ADRS:
    __slots__ = ("_buf", "type")

    def __init__(self):
        self._buf = bytearray(32)
        self.type = AdrsType(0)

    def copy(self) -> "ADRS":
        c = ADRS.__new__(ADRS)
        c._buf = bytearray(self._buf)
        c.type = self.type
        return c

    def to_bytes(self) -> bytes:
        return bytes(self._buf)

    # --- setters ------------------------------------------------------------
    def set_layer(self, layer: int) -> None:
        struct.pack_into(">I", self._buf, 0, layer)

    def set_tree(self, tree: int) -> None:
        # tree is a 96-bit big-endian int stored in [4:16]; SPHINCS+ uses a
        # 64-bit tree index packed into the low 8 bytes, so write zeros to
        # the high 4 bytes and the 64-bit value into [8:16].
        self._buf[4:8] = b"\x00\x00\x00\x00"
        struct.pack_into(">Q", self._buf, 8, tree)

    def set_type(self, type: "AdrsType") -> None:
        self.type = type
        struct.pack_into(">I", self._buf, 16, int(type))
        # Clear WORD1/2/3 to mirror the baseline's behaviour of zeroing the
        # per-type fields when the type changes.
        self._buf[20:32] = b"\x00" * 12

    def set_key_pair(self, key_pair: int) -> None:
        struct.pack_into(">I", self._buf, 20, key_pair)

    def set_chain(self, chain: int) -> None:
        struct.pack_into(">I", self._buf, 24, chain)

    def set_hash(self, hash: int) -> None:
        struct.pack_into(">I", self._buf, 28, hash)

    def set_tree_index(self, tree_index: int) -> None:
        struct.pack_into(">I", self._buf, 28, tree_index)

    def set_tree_height(self, tree_height: int) -> None:
        struct.pack_into(">I", self._buf, 24, tree_height)

    # --- getters ------------------------------------------------------------
    def get_key_pair(self) -> int:
        return struct.unpack_from(">I", self._buf, 20)[0]

    def get_tree_index(self) -> int:
        return struct.unpack_from(">I", self._buf, 28)[0]

    def get_tree_height(self) -> int:
        return struct.unpack_from(">I", self._buf, 24)[0]

    def __str__(self) -> str:
        return f"ADRS(type={self.type}, buf={bytes(self._buf).hex()})"

    def __repr__(self) -> str:
        return self.__str__()
