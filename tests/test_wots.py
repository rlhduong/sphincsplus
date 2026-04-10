import secrets
import pytest
from src.parameters import Parameters
from src.address import ADRS, AdrsType
from src.hash import hash, prf
from src.wots import chain, wots_gen_sk, wots_gen_pk, wots_sign, wots_pk_from_sig
from src.utils import base_w

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

def test_wots_key_gen(params: Parameters, seeds: tuple[bytes, bytes], adrs: ADRS):
    sk_seed, pk_seed = seeds
    sk = wots_gen_sk(sk_seed, adrs, params)
    pk = wots_gen_pk(sk_seed, pk_seed, adrs, params)

    tmp = []
    for i in range(params.wots_len):
        adrs.set_chain(i)
        adrs.set_hash(0)
        tmp.append(chain(sk[i], 0, params.w - 1, pk_seed, adrs, params))
    
    pk_adrs = adrs.copy()
    pk_adrs.set_type(AdrsType.WOTS_PK)
    pk_adrs.set_key_pair(adrs.get_key_pair())
    assert pk == hash(pk_seed, pk_adrs, b''.join(tmp), params)

    print(pk.hex())


def test_wots_sign(params: Parameters, seeds: tuple[bytes, bytes], adrs: ADRS, msg_digest: bytes):
    sk_seed, pk_seed = seeds
    pk = wots_gen_pk(sk_seed, pk_seed, adrs, params)
    sig = wots_sign(msg_digest, sk_seed, pk_seed, adrs, params)

    pk_from_sig = wots_pk_from_sig(sig, msg_digest, pk_seed, adrs, params)
    assert pk == pk_from_sig




    