import secrets
import pytest
from src.parameters import Parameters
from src.address import ADRS, AdrsType
from xmss import xmss_pk_gen, xmss_sign, xmss_pk_from_sig

def random_seed(length: int) -> bytes:
    return secrets.token_bytes(length)

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
    return bytes.fromhex("22" * params.n)

@pytest.fixture
def adrs():
    a = ADRS()
    a.set_type(AdrsType.WOTS_HASH)
    a.set_key_pair(0)
    return a

def test_xmss(params: Parameters, seeds: tuple[bytes, bytes], msg_digest: bytes, adrs: ADRS):
    sk_seed, pk_seed = seeds
    idx = 0

    # Generate public key
    pk = xmss_pk_gen(sk_seed, pk_seed, adrs.copy(), params)


    # Sign the message digest
    sig = xmss_sign(msg_digest, sk_seed, idx, pk_seed, adrs.copy(), params)

    # Derive public key from signature
    pk_from_sig = xmss_pk_from_sig(idx, sig, msg_digest, pk_seed, adrs.copy(), params)
    assert pk == pk_from_sig

    idx = 1
    sig = xmss_sign(msg_digest, sk_seed, idx, pk_seed, adrs.copy(), params)
    pk_from_sig = xmss_pk_from_sig(idx, sig, msg_digest, pk_seed, adrs.copy(), params)
    assert pk == pk_from_sig