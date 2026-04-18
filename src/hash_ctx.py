"""Pre-seeded hash context optimisation for SPHINCS+.

During a single `spx_sign` or `spx_verify` call, the same `pk_seed` is fed as
the first input to **every** tweakable hash `H(pk_seed, ADRS, val)`, and the
same `sk_seed` is fed as the first input to every `PRF(sk_seed, ADRS)` call.
The reference implementation of SPHINCS+ therefore pre-computes a hashlib
state with the seed already absorbed, and clones that state (via `.copy()`)
for each call. In Python this saves, per hash invocation:

* the cost of constructing a fresh `hashlib.sha256()` / `sha512()` object,
* the Python -> C boundary call that feeds in `pk_seed` (or `sk_seed`) every
  single time,
* the concat/buffering overhead of `.update(seed)` on a fresh object.

For a `sphincs-sha2-128s` signature this hot path runs ~2e6 times per sign
call, so even a few hundred nanoseconds saved per hash compounds into
seconds of wall-clock wins.

The resulting digests are **bit-for-bit identical** to the baseline code
path; this is purely an implementation-level optimisation and does not
change the signature format or security properties.
"""

from __future__ import annotations

from hashlib import sha256, sha512, shake_256

from src.parameters import Parameters


class HashCtx:
    """Holds pre-absorbed hashlib states for `pk_seed` and (optionally) `sk_seed`.

    Methods `h(adrs_bytes, val)` and `prf(adrs_bytes)` mirror the semantics of
    `src.hash.h` and `src.hash.prf` but skip re-absorbing the seed on every
    call by cloning a cached hashlib state.
    """

    __slots__ = ("_pk_base", "_sk_base", "_n", "_is_shake")

    def __init__(self, pk_seed: bytes, params: Parameters, sk_seed: bytes | None = None):
        self._n = params.n
        self._is_shake = params.hash_fn == "shake"

        self._pk_base = self._new_hash(params)
        self._pk_base.update(pk_seed)

        if sk_seed is not None:
            self._sk_base = self._new_hash(params)
            self._sk_base.update(sk_seed)
        else:
            self._sk_base = None

    @staticmethod
    def _new_hash(params: Parameters):
        if params.hash_fn == "sha256":
            return sha256()
        if params.hash_fn == "sha512":
            return sha512()
        if params.hash_fn == "shake":
            return shake_256()
        raise ValueError(f"Unsupported hash function: {params.hash_fn!r}")

    def h(self, adrs_bytes: bytes, val: bytes) -> bytes:
        c = self._pk_base.copy()
        c.update(adrs_bytes)
        c.update(val)
        if self._is_shake:
            return c.digest(self._n)
        return c.digest()[: self._n]

    def prf(self, adrs_bytes: bytes) -> bytes:
        if self._sk_base is None:
            raise RuntimeError("HashCtx was built without sk_seed; prf() unavailable")
        c = self._sk_base.copy()
        c.update(adrs_bytes)
        if self._is_shake:
            return c.digest(self._n)
        return c.digest()[: self._n]
