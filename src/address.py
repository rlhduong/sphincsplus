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


_LAYER  = slice(0,  4)      # layer address
_TREE   = slice(4,  16)     # tree address (64-bit big-endian)
_TYPE   = slice(16, 20)     # type
_WORD1  = slice(20, 24)     # keypair
_WORD2  = slice(24, 28)     # chain / tree-height
_WORD3  = slice(28, 32)     # hash  / tree-index


class ADRS:
    layer: bytearray
    tree: bytearray
    type: int
    key_pair: bytearray
    chain: bytearray
    hash: bytearray
    tree_index: bytearray
    tree_height: bytearray
    def __init__(self):
        self.layer = bytearray(4)
        self.tree  = bytearray(12)
        self.type  = AdrsType(0)
    
        self.key_pair = bytearray(4)
        self.chain = bytearray(4)
        self.hash = bytearray(4)
    
        self.tree_index = bytearray(4)
        self.tree_height = bytearray(4)

    def copy(self) -> 'ADRS':
        copy = ADRS()
        copy.layer[:] = self.layer
        copy.tree[:] = self.tree
        copy.type = self.type
        copy.key_pair[:] = self.key_pair
        copy.chain[:] = self.chain
        copy.hash[:] = self.hash
        copy.tree_index[:] = self.tree_index
        copy.tree_height[:] = self.tree_height
        return copy
    
    def to_bytes(self) -> bytes:
        ADRSc = bytearray(32)
        ADRSc[_LAYER] = self.layer
        ADRSc[_TREE] = self.tree
        ADRSc[_TYPE] = struct.pack('>I', self.type)

        if self.type == AdrsType.WOTS_HASH:
            ADRSc[_WORD1] = self.key_pair
            ADRSc[_WORD2] = self.chain
            ADRSc[_WORD3] = self.hash
        elif self.type == AdrsType.WOTS_PK:
            ADRSc[_WORD1] = self.key_pair
        elif self.type == AdrsType.TREE:
            ADRSc[_WORD2] = self.tree_height
            ADRSc[_WORD3] = self.tree_index
        elif self.type == AdrsType.FORS_TREE:
            ADRSc[_WORD1] = self.key_pair
            ADRSc[_WORD2] = self.tree_height
            ADRSc[_WORD3] = self.tree_index
        elif self.type == AdrsType.FORS_ROOTS:
            ADRSc[_WORD1] = self.key_pair
        elif self.type == AdrsType.WOTS_PRF:
            ADRSc[_WORD1] = self.key_pair
            ADRSc[_WORD2] = self.chain
        elif self.type == AdrsType.FORS_PRF:
            ADRSc[_WORD1] = self.key_pair
            ADRSc[_WORD3] = self.tree_index

        return bytes(ADRSc)
    
    def set_layer(self, layer: int):
        self.layer = struct.pack('>I', layer)

    def set_tree(self, tree: int):
        self.tree = struct.pack('>Q', tree)

    def set_type(self, type: AdrsType):
        self.type = type
        self.key_pair = bytearray(4)
        self.chain = bytearray(4)
        self.hash = bytearray(4)
        self.tree_index = bytearray(4)
        self.tree_height = bytearray(4)

    def set_key_pair(self, key_pair: int):
        self.key_pair = struct.pack('>I', key_pair)

    def set_chain(self, chain: int):
        self.chain = struct.pack('>I', chain)  

    def set_hash(self, hash: int):
        self.hash = struct.pack('>I', hash)
    
    def set_tree_index(self, tree_index: int):
        self.tree_index = struct.pack('>I', tree_index)

    def set_tree_height(self, tree_height: int):
        self.tree_height = struct.pack('>I', tree_height)

    def get_key_pair(self) -> int:
        return struct.unpack('>I', self.key_pair)[0]
    
    def get_tree_index(self) -> int:
        return struct.unpack('>I', self.tree_index)[0]
    
    def get_tree_height(self) -> int:
        return struct.unpack('>I', self.tree_height)[0]

    def __str__(self) -> str:
        return f"ADRS(layer={self.layer.hex()}, tree={self.tree.hex()}, type={self.type}, key_pair={self.key_pair.hex()}, chain={self.chain.hex()}, hash={self.hash.hex()}, tree_index={self.tree_index.hex()}, tree_height={self.tree_height.hex()})"

    def __repr__(self) -> str:
        return self.__str__()


        