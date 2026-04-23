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
    """Deterministic ``sphincs-sha2-128s`` with randomised signing disabled."""
    p = Parameters.get_paramset("sphincs-sha2-128s")
    p.set_RANDOMIZE(False)
    return p


def _with_mode(flag: bool, fn, *args, **kwargs):
    """Execute ``fn(*args, **kwargs)`` with ``OPTIMISED`` set to ``flag``, restoring the original value afterwards."""
    prev = sphincs_mod.OPTIMISED
    sphincs_mod.set_optimised(flag)
    try:
        return fn(*args, **kwargs)
    finally:
        sphincs_mod.set_optimised(prev)


def test_optimised_roundtrip(params: Parameters):
    """Optimised keygen → sign → verify must round-trip; wrong message must fail."""
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


# ---------------------------------------------------------------------------
# Optimisation 4 — ADRS snapshot (h_adrs_bytes)
# ---------------------------------------------------------------------------


def test_h_adrs_bytes_matches_h(params: Parameters):
    """h_adrs_bytes(pk_seed, adrs.to_bytes(), val) must equal h(pk_seed, adrs, val)
    for every AdrsType, both with and without a HashCtx active."""
    import secrets
    from src.address import ADRS, AdrsType
    from src.hash import h, h_adrs_bytes, set_hash_ctx, clear_hash_ctx
    from src.hash_ctx import HashCtx

    pk_seed = secrets.token_bytes(params.n)
    val = secrets.token_bytes(params.n * 2)

    for adrs_type in AdrsType:
        adrs = ADRS()
        adrs.set_type(adrs_type)
        adrs.set_key_pair(7)
        adrs.set_chain(3)
        adrs.set_hash(1)

        # baseline path (no HashCtx)
        expected = h(pk_seed, adrs, val, params)
        got = h_adrs_bytes(pk_seed, adrs.to_bytes(), val, params)
        assert expected == got, (
            f"h_adrs_bytes mismatch (no ctx) for AdrsType.{adrs_type.name}"
        )

        # optimised path (HashCtx active)
        ctx = HashCtx(pk_seed, params)
        set_hash_ctx(ctx)
        try:
            expected_ctx = h(pk_seed, adrs, val, params)
            got_ctx = h_adrs_bytes(pk_seed, adrs.to_bytes(), val, params)
        finally:
            clear_hash_ctx()

        assert expected_ctx == got_ctx, (
            f"h_adrs_bytes mismatch (with ctx) for AdrsType.{adrs_type.name}"
        )
        assert expected == expected_ctx, (
            f"h() differs baseline vs HashCtx for AdrsType.{adrs_type.name}"
        )


def test_opt4_end_to_end(params: Parameters):
    """Full sign/verify round-trip with Opt-4 active (h_adrs_bytes in xmss)."""
    import secrets as _s

    counter = {"i": 0}
    real_token_bytes = _s.token_bytes

    def fake_token_bytes(n: int) -> bytes:
        counter["i"] += 1
        return bytes([counter["i"] % 256] * n)

    _s.token_bytes = fake_token_bytes
    try:
        counter["i"] = 0
        sphincs_mod.set_optimised(True)
        sk, pk = spx_keygen(params)
        msg = b"opt4 parity"
        sig = spx_sign(msg, sk, params)
        assert spx_verify(msg, sig, pk, params), "Opt-4 signature failed to verify"
        assert not spx_verify(b"wrong message", sig, pk, params), (
            "Opt-4 accepted wrong message"
        )
    finally:
        _s.token_bytes = real_token_bytes
        sphincs_mod.set_optimised(True)
