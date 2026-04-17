from hashlib import sha256, sha512, shake_256

from address import ADRS
from parameters import Parameters


def h_msg(r: bytes, pk_seed: bytes, pk_root: bytes, msg: bytes, params: Parameters) -> bytes:
    if params.hash_fn == 'sha256':
        h = sha256()
    elif params.hash_fn == 'sha512':
        h = sha512()
    elif params.hash_fn == 'shake':
        h = shake_256()
    
    h.update(r)
    h.update(pk_seed)
    h.update(pk_root)
    h.update(msg)

    return h.digest()[:params.m]


def h(pk_seed: bytes, adrs: ADRS, val: bytes, params: Parameters) -> bytes:
    if params.hash_fn == 'sha256':
        h = sha256()
    elif params.hash_fn == 'sha512':
        h = sha512()
    elif params.hash_fn == 'shake':
        h = shake_256()
    
    h.update(pk_seed)
    h.update(adrs.to_bytes())
    h.update(val)

    return h.digest()[:params.n]


def prf(sk_seed: bytes, adrs: ADRS, params: Parameters) -> bytes:
    if params.hash_fn == 'sha256':
        h = sha256()
    elif params.hash_fn == 'sha512':
        h = sha512()
    elif params.hash_fn == 'shake':
        h = shake_256()
    
    h.update(sk_seed)
    h.update(adrs.to_bytes())

    return h.digest()[:params.n]

def prf_msg(sk_seed: bytes, opt: bytes, msg: bytes, params: Parameters) -> bytes:
    if params.hash_fn == 'sha256':
        h = sha256()
    elif params.hash_fn == 'sha512':
        h = sha512()
    elif params.hash_fn == 'shake':
        h = shake_256()
    
    h.update(sk_seed)
    h.update(opt)   
    h.update(msg)

    return h.digest()[:params.n]