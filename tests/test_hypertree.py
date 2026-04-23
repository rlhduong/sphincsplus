"""Hypertree round-trip test: sign, verify, and reject a corrupted signature."""

import secrets
import pytest
from src.parameters import Parameters
from src.address import ADRS, AdrsType
from src.hypertree import hypertree_verify, hypertree_sign, hypertree_gen_pk


def random_seed(length: int) -> bytes:
    """Return a random ``length``-byte seed."""
    return secrets.token_bytes(length)


@pytest.fixture
def params() -> Parameters:
    """``sphincs-sha2-128s`` parameter set."""
    return Parameters.get_paramset("sphincs-sha2-128s")


@pytest.fixture
def seeds(params: Parameters) -> tuple[bytes, bytes]:
    """Random ``(sk_seed, pk_seed)`` pair."""
    sk_seed = random_seed(params.n)
    pk_seed = random_seed(params.n)
    return sk_seed, pk_seed


@pytest.fixture
def msg_digest(params: Parameters) -> bytes:
    """Deterministic ``n``-byte message digest (all 0x22)."""
    return bytes.fromhex("22" * params.n)


@pytest.fixture
def adrs():
    """``WOTS_HASH``-typed address at ``key_pair=0``."""
    a = ADRS()
    a.set_type(AdrsType.WOTS_HASH)
    a.set_key_pair(0)
    return a


def test_hypertree(
    params: Parameters, seeds: tuple[bytes, bytes], msg_digest: bytes, adrs: ADRS
):
    """Valid signature must verify; flipping the last byte must be rejected."""
    sk_seed, pk_seed = seeds
    idx_tree = 0
    idx_leaf = 0

    pk_ht = hypertree_gen_pk(sk_seed, pk_seed, params)

    sig_ht = hypertree_sign(msg_digest, sk_seed, pk_seed, idx_tree, idx_leaf, params)

    assert hypertree_verify(
        msg_digest, sig_ht, pk_seed, idx_tree, idx_leaf, pk_ht, params
    )

    sig_ht_invalid = sig_ht[:-1] + bytes([sig_ht[-1] ^ 0xFF])
    assert not hypertree_verify(
        msg_digest, sig_ht_invalid, pk_seed, idx_tree, idx_leaf, pk_ht, params
    )
