from hashlib import sha256, shake_256

from address import ADRS
from parameters import Parameters


def hash(pk_seed: bytes, adrs: ADRS, val: bytes, params: Parameters) -> bytes:
    if params.hash_fn == 'sha256':
        h = sha256()
    elif params.hash_fn == 'shake256':
        h = shake_256()
    
    h.update(pk_seed)
    h.update(adrs.to_bytes())
    h.update(val)

    return h.digest()[:params.n]


def prf(sk_seed: bytes, adrs: ADRS, params: Parameters) -> bytes:
    if params.hash_fn == 'sha256':
        h = sha256()
    elif params.hash_fn == 'shake256':
        h = shake_256()
    
    h.update(sk_seed)
    h.update(adrs.to_bytes())

    return h.digest()[:params.n]

def prf_msg(sk_seed: bytes, adrs: ADRS, params: Parameters, msg: bytes) -> bytes:
    if params.hash_fn == 'sha256':
        h = sha256()
    elif params.hash_fn == 'shake256':
        h = shake_256()
    
    h.update(sk_seed)
    h.update(adrs.to_bytes())
    h.update(msg)

    return h.digest()[:params.n]