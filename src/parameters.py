"""SPHINCS+ parameter sets.

Naming convention::

    sphincs-{hash}-{n*8}{s|f}
        hash : sha2 | shake
        n*8  : 128 | 192 | 256   (security level in bits)
        s|f  : small (few sigs, small keys) | fast (many sigs, fast signing)

Field glossary::

    n        security parameter in bytes (also the hash output length)
    w        Winternitz parameter for WOTS+ (chain length = w)
    h        total height of the hypertree (sum over all d layers)
    d        number of layers in the hypertree
    k        number of trees in FORS
    t        number of leaves per FORS tree (t = 2**a)
    a        height of a FORS tree = log2(t)
    m        message-digest length (bytes) fed to the hypertree
    hash_fn  'sha256' | 'sha512' | 'shake'
"""

import math


class Parameters:
    """Concrete SPHINCS+ parameter set.

    Instances are normally built through :meth:`get_paramset`; the raw
    constructor is exposed so tests can experiment with non-standard
    combinations. Derived quantities (``len1``, ``len2``, ``h_prime``,
    ``wots_len``, ``m``) are computed from the primary fields and follow
    the formulas in the SPHINCS+ specification.
    """

    #: Standardised parameter sets keyed by name. Values are the primary
    #: inputs passed to ``__init__`` (n, w, h, d, k, log_t, hash_fn).
    default_parameters = {
        "sphincs-sha2-128s": (16, 16, 63, 7, 14, 12, "sha256"),
        "sphincs-sha2-128f": (16, 16, 66, 22, 33, 6, "sha256"),
        "sphincs-sha2-192s": (24, 16, 63, 7, 17, 14, "sha512"),
        "sphincs-sha2-192f": (24, 16, 66, 22, 33, 8, "sha512"),
        "sphincs-sha2-256s": (32, 16, 64, 8, 22, 14, "sha512"),
        "sphincs-sha2-256f": (32, 16, 68, 17, 35, 9, "sha512"),
        "sphincs-shake-128s": (16, 16, 63, 7, 14, 12, "shake"),
        "sphincs-shake-128f": (16, 16, 66, 22, 33, 6, "shake"),
        "sphincs-shake-192s": (24, 16, 63, 7, 17, 14, "shake"),
        "sphincs-shake-192f": (24, 16, 66, 22, 33, 8, "shake"),
        "sphincs-shake-256s": (32, 16, 64, 8, 22, 14, "shake"),
        "sphincs-shake-256f": (32, 16, 68, 17, 35, 9, "shake"),
    }

    def __init__(
        self, n: int, w: int, h: int, d: int, k: int, log_t: int, hash_fn: str
    ):
        """Initialise a parameter set and derive ``len1``, ``len2`` and ``h_prime``.

        ``log_t`` is the FORS tree height ``a``; the number of leaves per
        FORS tree is ``t = 2**a``. ``len1`` and ``len2`` are the
        message-digest and checksum parts of the WOTS+ signature vector.
        ``h_prime = h / d`` is the height of a single XMSS layer.
        """
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
        self.RANDOMIZE = True

    def set_RANDOMIZE(self, randomize: bool):
        """Enable/disable the randomised signing mode.

        When ``True`` (the default), ``spx_sign`` draws a fresh ``opt``
        randomiser per signature. When ``False``, ``opt = pk_seed`` which
        produces deterministic signatures - used by tests and benchmarks for
        reproducibility.
        """
        self.RANDOMIZE = randomize

    @property
    def wots_len(self) -> int:
        """Total number of ``n``-byte blocks in a WOTS+ signature (``len1 + len2``)."""
        return self.len1 + self.len2

    def len_md(self) -> int:
        """Byte length of the FORS message-digest slice carved from ``H_msg`` output."""
        return math.floor((self.k * self.log_t + 7) / 8)

    def idx_tree_len(self) -> int:
        """Byte length of the hypertree ``idx_tree`` slice carved from ``H_msg`` output."""
        return math.floor((self.h - self.h / self.d + 7) / 8)

    def idx_leaf_len(self) -> int:
        """Byte length of the ``idx_leaf`` slice carved from ``H_msg`` output."""
        return math.floor((self.h / self.d + 7) / 8)

    @property
    def m(self) -> int:
        """Total message-digest length fed to the hypertree (``len_md + idx_tree + idx_leaf``)."""
        return self.len_md() + self.idx_tree_len() + self.idx_leaf_len()

    @classmethod
    def get_paramset(cls, name: str) -> "Parameters":
        """Look up a standardised parameter set by name (e.g. ``sphincs-sha2-128s``)."""
        n, w, h, d, k, log_t, hash_fn = cls.default_parameters[name]
        return Parameters(n, w, h, d, k, log_t, hash_fn)

    def __str__(self) -> str:
        return f"Parameters(n={self.n}, w={self.w}, h={self.h}, d={self.d}, k={self.k}, log_t={self.log_t})"
