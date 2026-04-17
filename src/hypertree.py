from address import ADRS
from parameters import Parameters
from xmss import xmss_pk_gen, xmss_sign, xmss_pk_from_sig


def get_xmss_sig_by_level(sig_ht: bytes, level: int, params: Parameters) -> bytes:
    xmss_len = params.n *(params.wots_len + params.h_prime)
    return sig_ht[level * xmss_len : (level + 1) * xmss_len]

def hypertree_gen_pk(sk_seed: bytes, pk_seed: bytes, params: Parameters) -> bytes:
    adrs= ADRS() 
    adrs.set_layer(params.d - 1)
    adrs.set_tree(0)
    root = xmss_pk_gen(sk_seed, pk_seed, adrs, params)
    return root

def hypertree_sign(msg_digest: bytes, sk_seed: bytes, pk_seed: bytes, idx_tree: int, idx_leaf: int, params: Parameters) -> bytes:
    adrs = ADRS()
    adrs.set_layer(0)
    adrs.set_tree(idx_tree)
    sig_tmp = xmss_sign(msg_digest, sk_seed, idx_leaf, pk_seed, adrs.copy(), params)

    sig_ht = sig_tmp
    root = xmss_pk_from_sig(idx_leaf, sig_tmp, msg_digest, pk_seed, adrs, params)

    for j in range(1, params.d):
        idx_leaf = idx_tree & ((1 << params.h_prime) - 1)
        idx_tree >>= params.h_prime

        adrs.set_layer(j)
        adrs.set_tree(idx_tree)
        sig_tmp = xmss_sign(root, sk_seed, idx_leaf, pk_seed, adrs, params)
        sig_ht += sig_tmp

        if j < params.d - 1:
            root = xmss_pk_from_sig(idx_leaf, sig_tmp, root, pk_seed, adrs, params)
    
    return sig_ht

def hypertree_verify(msg_digest: bytes, sig_ht: bytes, pk_seed: bytes, idx_tree: int, idx_leaf: int, params: Parameters, pk_ht: bytes) -> bool:
    adrs = ADRS()
    adrs.set_layer(0)
    adrs.set_tree(idx_tree)

    sig_tmp = get_xmss_sig_by_level(sig_ht, 0, params)
    node = xmss_pk_from_sig(idx_leaf, sig_tmp, msg_digest, pk_seed, adrs, params)

    for j in range(1, params.d):
        idx_leaf = idx_tree & ((1 << params.h_prime) - 1)
        idx_tree >>= params.h_prime
        sig_tmp = get_xmss_sig_by_level(sig_ht, j, params)
        adrs.set_layer(j)
        adrs.set_tree(idx_tree)
        node = xmss_pk_from_sig(idx_leaf, sig_tmp, node, pk_seed, adrs, params)

    return node == pk_ht
        

    



