import math
from address import ADRS, AdrsType
from parameters import Parameters
from wots import wots_gen_pk, wots_sign, wots_pk_from_sig
from utils import auth_path_to_array
from hash import h, prf

def get_idx_from_msg(msg_digest: bytes, i: int, params: Parameters) -> int:
    bits = len(msg_digest) * 8
    value = int.from_bytes(msg_digest, byteorder='big')

    idx = (value >> (bits - (i + 1) * params.a)) & ((1 << params.a) - 1)
    return idx

def get_sk_from_sig(sig_fors: bytes, i: int, params: Parameters) -> bytes:
    sk_len = params.n
    return sig_fors[i * (sk_len + params.a * params.n) : i * (sk_len + params.a * params.n) + sk_len]

def get_auth_path_from_sig(sig_fors: bytes, i: int, params: Parameters) -> list[bytes]:
    auth_path = []
    for j in range(0, params.a):
        start = i * (params.n + params.a * params.n) + params.n + j * params.n
        end = start + params.n
        auth_path.append(sig_fors[start:end])
    return auth_path

def fors_sk_gen(sk_seed: bytes, adrs: ADRS, idx: int, params: Parameters) -> bytes:
    sk_adrs = adrs.copy()
    sk_adrs.set_type(AdrsType.FORS_PRF)
    sk_adrs.set_key_pair(adrs.get_key_pair())

    sk_adrs.set_tree_height(0)
    sk_adrs.set_tree_index(idx)
    sk = prf(sk_seed, sk_adrs, params)
    return sk

def fors_treehash(sk_seed: bytes, s: int, z: int, pk_seed: bytes, adrs: ADRS, params: Parameters) -> bytes:
    if s % (1 << z) != 0:
        return -1
   
    stack = []

    for i in range(0, 1 << z):
        sk = fors_sk_gen(sk_seed, adrs, s + i, params)
        node = h(pk_seed, adrs.copy(), sk, params)

        adrs.set_tree_height(1)
        adrs.set_tree_index(s + i)

        while len(stack) > 0 and stack[-1][1] == adrs.get_tree_height():
            adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
            node = h(pk_seed, adrs.copy(), stack.pop()[0] + node, params)
            adrs.set_tree_height(adrs.get_tree_height() + 1)
        
        stack.append((node, adrs.get_tree_height()))

    return stack[-1][0]

def fors_pk_gen(sk_seed: bytes, pk_seed: bytes, adrs: ADRS, params: Parameters) -> bytes:
    t = 1 << params.a
    fors_pk_adrs = adrs.copy()
    root = b''

    for i in range(0, params.k):
        root += fors_treehash(sk_seed, i * t, params.a, pk_seed, adrs.copy(), params)

    fors_pk_adrs.set_type(AdrsType.FORS_ROOTS)
    fors_pk_adrs.set_key_pair(adrs.get_key_pair())

    pk = h(pk_seed, fors_pk_adrs, root, params)
    return pk
    
### msg_digest floor((k * log_t + 7) // 8) bytes
def fors_sign(msg_digest: bytes, sk_seed: bytes, pk_seed: bytes, adrs: ADRS, params: Parameters) -> bytes:
    t = 1 << params.a
    sig_fors = b''

    for i in range(0, params.k):
        idx = get_idx_from_msg(msg_digest, i, params)

        sig_fors += fors_sk_gen(sk_seed, adrs, i * t + idx, params)

        auth_path = b''
        for j in range(0, params.a):
            s = (idx // (1 << j)) ^ 1
            auth_path += fors_treehash(sk_seed, i * t + s * (1 << j), j, pk_seed, adrs.copy(), params)
        
        sig_fors += auth_path
    return sig_fors

def fors_pk_from_sig(sig_fors: bytes, msg_digest: bytes, pk_seed: bytes, adrs: ADRS, params: Parameters) -> bytes:
    t = 1 << params.a
    root = b''
    node_0 = b''
    node_1 = node_0

    for i in range(0, params.k):
        idx = get_idx_from_msg(msg_digest, i, params)

        sk = get_sk_from_sig(sig_fors, i, params)
        adrs.set_tree_height(0)
        adrs.set_tree_index(i * t + idx)
        node_0 = h(pk_seed, adrs.copy(), sk, params)

        auth_path = get_auth_path_from_sig(sig_fors, i, params)
        adrs.set_tree_index(i * t + idx)

        for j in range(0, params.a):
            adrs.set_tree_height(j + 1)
            if (idx // (1 << j)) % 2 == 0:
                adrs.set_tree_index(adrs.get_tree_index() // 2)
                node_1 = h(pk_seed, adrs.copy(), node_0 + auth_path[j], params)
            else:
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node_1 = h(pk_seed, adrs.copy(), auth_path[j] + node_0, params)
            node_0 = node_1
        root += node_0

    fors_pk_adrs = adrs.copy()
    fors_pk_adrs.set_type(AdrsType.FORS_ROOTS)
    fors_pk_adrs.set_key_pair(adrs.get_key_pair())
    pk = h(pk_seed, fors_pk_adrs, root, params)
    return pk
