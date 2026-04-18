"""Tests for the pre-absorbed HashCtx optimisation.

Verifies that:
1. The optimised path signs and verifies correctly (round-trip).
2. The optimised path is bit-for-bit identical to the baseline path:
   - Same (sk, pk) from a seeded keygen (with the RANDOMIZE=False switch
     to make signing deterministic).
   - Same signature bytes under both modes.
   - Cross-verification: signatures from each path verify under the other.
"""

import pytest

import src.sphincs as sphincs_mod
from src.parameters import Parameters
from src.sphincs import spx_keygen, spx_sign, spx_verify


@pytest.fixture
def params() -> Parameters:
    p = Parameters.get_paramset("sphincs-sha2-128s")
    p.set_RANDOMIZE(False)
    return p


def _with_mode(flag: bool, fn, *args, **kwargs):
    prev = sphincs_mod.OPTIMISED
    sphincs_mod.set_optimised(flag)
    try:
        return fn(*args, **kwargs)
    finally:
        sphincs_mod.set_optimised(prev)


def test_optimised_roundtrip(params: Parameters):
    sk, pk = _with_mode(True, spx_keygen, params)
    msg = b"optimised roundtrip"
    sig = _with_mode(True, spx_sign, msg, sk, params)
    assert _with_mode(True, spx_verify, msg, sig, pk, params)
    assert not _with_mode(True, spx_verify, b"different message", sig, pk, params)


def test_baseline_and_optimised_produce_identical_signatures(params: Parameters):
    """The optimisation is implementation-level only: outputs must match."""

    # Seed keygen deterministically by monkey-patching secrets.token_bytes.
    import secrets as _s

    counter = {"i": 0}
    real_token_bytes = _s.token_bytes

    def fake_token_bytes(n: int) -> bytes:
        counter["i"] += 1
        return bytes([counter["i"] % 256] * n)

    _s.token_bytes = fake_token_bytes
    try:
        counter["i"] = 0
        sk_a, pk_a = _with_mode(False, spx_keygen, params)
        counter["i"] = 0
        sk_b, pk_b = _with_mode(True, spx_keygen, params)
        assert sk_a == sk_b
        assert pk_a == pk_b

        msg = b"parity check"
        # Sign under each mode (RANDOMIZE is off, so signing is deterministic).
        sig_a = _with_mode(False, spx_sign, msg, sk_a, params)
        sig_b = _with_mode(True, spx_sign, msg, sk_b, params)
        assert sig_a == sig_b, "optimised path diverged from baseline"

        # Cross-verify: each mode accepts the other's signature.
        assert _with_mode(False, spx_verify, msg, sig_b, pk_b, params)
        assert _with_mode(True, spx_verify, msg, sig_a, pk_a, params)
    finally:
        _s.token_bytes = real_token_bytes
