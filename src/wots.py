from address import ADRS, AdrsType
from parameters import Parameters
from utils import base_w, sig_to_array
import math
from hash import h, prf


def chain(x: bytes, i: int, s: int, pk_seed: bytes, adrs: ADRS, params: Parameters) -> bytes:
    if i + s > params.w:
        return None
    
    for k in range(s):
        adrs.set_hash(i + k)
        x = h(pk_seed, adrs, x, params)
    return x

def wots_gen_sk(sk_seed: bytes, adrs: ADRS, params: Parameters) -> list[bytes]:
    sk_adrs = adrs.copy()
    sk_adrs.set_type(AdrsType.WOTS_PRF)
    sk_adrs.set_key_pair(adrs.get_key_pair())
    sk = []

    for i in range(0, params.wots_len):
        sk_adrs.set_chain(i)
        sk_adrs.set_hash(0)
        sk.append(prf(sk_seed, sk_adrs, params))

    return sk

def wots_gen_pk(sk_seed: bytes, pk_seed: bytes, adrs: ADRS, params: Parameters) -> bytes:
    pk_adrs = adrs.copy()
    sk_adrs = adrs.copy()
    sk_adrs.set_type(AdrsType.WOTS_PRF)
    sk_adrs.set_key_pair(adrs.get_key_pair())

    tmp = []
    sk = []

    for i in range(0, params.wots_len):
        sk_adrs.set_chain(i)
        sk_adrs.set_hash(0)
        sk.append(prf(sk_seed, sk_adrs, params))

        adrs.set_chain(i)
        adrs.set_hash(0)
        tmp.append(chain(sk[i], 0, params.w - 1, pk_seed, adrs, params))

    pk_adrs.set_type(AdrsType.WOTS_PK)
    pk_adrs.set_key_pair(adrs.get_key_pair())
    pk = h(pk_seed, pk_adrs, b''.join(tmp), params)

    return pk

def wots_sign(msg_digest: bytes, sk_seed: bytes, pk_seed: bytes, adrs: ADRS, params: Parameters) -> bytes:
    csum = 0

    msg_base_w = base_w(msg_digest, params.w, params.len1)

    for i in range(0, params.len1):
        csum += params.w - 1 - msg_base_w[i]

    pad = (8 - ((params.len2 * params.log_w) % 8)) % 8
    csum <<= pad

    csum_bytes = csum.to_bytes(math.ceil((params.len2 * params.log_w) / 8), byteorder='big')
    csum_base_w = base_w(csum_bytes, params.w, params.len2)
    msg_base_w += csum_base_w

    sk_adrs = adrs.copy()
    sk_adrs.set_type(AdrsType.WOTS_PRF)
    sk_adrs.set_key_pair(adrs.get_key_pair())
    tmp = []
    for i in range(0, params.wots_len):
        sk_adrs.set_chain(i)
        sk_adrs.set_hash(0)
        sk = prf(sk_seed, sk_adrs, params)

        adrs.set_chain(i)
        adrs.set_hash(0)
        tmp.append(chain(sk, 0, msg_base_w[i], pk_seed, adrs, params))

    sig = b''.join(tmp)
    return sig


def wots_pk_from_sig(sig: bytes, msg_digest: bytes, pk_seed: bytes, adrs: ADRS, params: Parameters) -> bytes:
    csum = 0

    msg_base_w = base_w(msg_digest, params.w, params.len1)

    for i in range(0, params.len1):
        csum += params.w - 1 - msg_base_w[i]

    pad = (8 - ((params.len2 * params.log_w) % 8)) % 8
    csum <<= pad

    csum_bytes = csum.to_bytes(math.ceil((params.len2 * params.log_w) / 8), byteorder='big')
    csum_base_w = base_w(csum_bytes, params.w, params.len2)
    msg_base_w += csum_base_w

    sig_array = sig_to_array(sig, params.n)
    tmp = []
    for i in range(0, params.wots_len):
        adrs.set_chain(i)
        adrs.set_hash(0)
        tmp.append(chain(sig_array[i], msg_base_w[i], params.w - 1 - msg_base_w[i], pk_seed, adrs, params))
    
    pk_adrs = adrs.copy()
    pk_adrs.set_type(AdrsType.WOTS_PK)
    pk_adrs.set_key_pair(adrs.get_key_pair())
    return h(pk_seed, pk_adrs, b''.join(tmp), params)
