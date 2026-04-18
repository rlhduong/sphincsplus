import secrets
import pytest
from src.parameters import Parameters
from src.address import ADRS, AdrsType
from src.fors import fors_sign, fors_sk_gen, fors_pk_gen, fors_pk_from_sig
import math
def random_seed(length: int) -> bytes:
    return bytes.fromhex("11" * length)

@pytest.fixture
def params() -> Parameters:
    return Parameters.get_paramset("sphincs-sha2-128s")

@pytest.fixture
def seeds(params: Parameters) -> tuple[bytes, bytes]:
    sk_seed = random_seed(params.n)
    pk_seed = random_seed(params.n)
    return sk_seed, pk_seed

@pytest.fixture
def msg_digest(params: Parameters) -> bytes:
    return bytes.fromhex("22" * math.floor((params.k * params.log_t + 7) / 8))

@pytest.fixture
def adrs():
    # spx_sign / spx_verify always call fors_sign / fors_pk_from_sig with a
    # FORS_TREE-typed address (see src/sphincs.py). Using WOTS_HASH here only
    # happened to work under the old `ADRS.to_bytes()` implementation because
    # it silently dropped tree_height/tree_index writes for non-TREE types.
    # Using the semantically correct type makes the test robust against ADRS
    # refactors.
    a = ADRS()
    a.set_type(AdrsType.FORS_TREE)
    a.set_key_pair(0)
    return a


def test_fors(msg_digest: bytes, seeds: tuple[bytes, bytes], adrs: ADRS, params: Parameters) -> bytes:
    sk_seed, pk_seed = seeds
    pk_fors = fors_pk_gen(sk_seed, pk_seed, adrs, params)
    sig_fors = fors_sign(msg_digest, sk_seed, pk_seed, adrs, params)
    pk_fors_from_sig = fors_pk_from_sig(sig_fors, msg_digest, pk_seed, adrs, params)
    assert pk_fors == pk_fors_from_sig
