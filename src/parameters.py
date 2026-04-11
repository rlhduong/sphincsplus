"""
Parameter set naming convention:
    sphincs-{hash}-{n*8}{s|f}
        hash : sha2 | shake
        n*8  : 128 | 192 | 256   (security level in bits)
        s|f  : small (few sigs, small keys) | fast (many sigs, fast signing)

name: sphincs-{hash}-{n*8}{s|f}
n : the security parameter in bytes.
w : the Winternitz parameter.
h : the height of the hypertree.
d : the number of layers in the hypertree.
k : the number of trees in FORS.
t : the number of leaves of a FORS tree.
a : the height of a FORS tree. log2(t)
m : the message digest length (bytes)
hash    : "sha2" or "shake"
"""


import math


class Parameters:
    default_parameters = {
        "sphincs-sha2-128s": (16, 16, 63, 7, 14, 12, 'sha256'),
        "sphincs-sha2-128f": (16, 16, 66, 22, 33, 6, 'sha256'),
        "sphincs-sha2-192s": (24, 16, 63, 7, 17, 14, 'sha256'),
        "sphincs-sha2-192f": (24, 16, 66, 22, 33, 8, 'sha256'),
        "sphincs-sha2-256s": (32, 16, 64, 8, 22, 14, 'sha256'),
        "sphincs-sha2-256f": (32, 16, 68, 17, 35, 9, 'sha256'),

        "sphincs-shake-128s": (16, 16, 63, 7, 14, 12, 'shake256'),
        "sphincs-shake-128f": (16, 16, 66, 22, 33, 6, 'shake256'),
        "sphincs-shake-192s": (24, 16, 63, 7, 17, 14, 'shake256'),
        "sphincs-shake-192f": (24, 16, 66, 22, 33, 8, 'shake256'),
        "sphincs-shake-256s": (32, 16, 64, 8, 22, 14, 'shake256'),
        "sphincs-shake-256f": (32, 16, 68, 17, 35, 9, 'shake256'),
    }
        
    def __init__(self, n: int, w: int, h: int, d: int, k: int, log_t: int, hash_fn: str):
        self.n = n
        self.w = w
        self.h = h
        self.d = d
        self.k = k
        self.log_t = log_t
        self.a = log_t
        self.hash_fn = hash_fn
        self.log_w = int(math.log2(w))
        self.len1 = math.ceil((8 * self.n) / self.log_w)
        self.len2 = math.floor(math.log2(self.len1 * (self.w - 1)) / self.log_w) + 1
        self.h_prime = self.h // self.d

    @property
    def wots_len(self) -> int:
        return self.len1 + self.len2

    @property
    def m(self) -> int:
        return math.floor((self.k * self.log_t + 7) / 8) + math.floor((self.h - self.h / self.d + 7) / 8) + math.floor((self.h / self.d + 7) / 8)
    
    @classmethod
    def get_paramset(cls, name: str) -> 'Parameters':
        n, w, h, d, k, log_t, hash_fn = cls.default_parameters[name]
        return Parameters(n, w, h, d, k, log_t, hash_fn)
    
    def __str__(self) -> str:
        return f"Parameters(n={self.n}, w={self.w}, h={self.h}, d={self.d}, k={self.k}, log_t={self.log_t})"
    
