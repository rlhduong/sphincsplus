import hashlib
import secrets
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

from src.parameters import Parameters
from src.address import ADRS, AdrsType
from src.sphincs import spx_keygen, spx_sign, spx_verify
from src.wots import wots_gen_pk, wots_sign, wots_pk_from_sig


USER_BYTES = 8
ZETA_BYTES = 16


# Feistel cipher used to encrypt (user_id, counter) into zeta.
# This lets the manager trace signatures back to users while keeping
# the identity hidden from verifiers.

def _f(key: bytes, data: bytes, r: int) -> bytes:
    return hashlib.sha256(key + r.to_bytes(1, 'big') + data).digest()[:8]

def _encrypt(key: bytes, block: bytes) -> bytes:
    L, R = block[:8], block[8:]
    for i in range(4):
        L, R = R, bytes(a ^ b for a, b in zip(L, _f(key, R, i)))
    return L + R

def _decrypt(key: bytes, block: bytes) -> bytes:
    L, R = block[:8], block[8:]
    for i in range(3, -1, -1):
        R, L = L, bytes(a ^ b for a, b in zip(R, _f(key, L, i)))
    return L + R


def _hn(data: bytes, params: Parameters) -> bytes:
    if params.hash_fn == 'shake':
        return hashlib.shake_256(data).digest(params.n)
    if params.n <= 32:
        return hashlib.sha256(data).digest()[:params.n]
    return hashlib.sha512(data).digest()[:params.n]


@dataclass
class Certificate:
    zeta: bytes
    pi: bytes
    spx_sig: bytes


@dataclass
class GroupSignature:
    wots_sig: bytes
    wots_seed: bytes
    zeta: bytes
    spx_sig: bytes
    tau: bytes


class MembershipList:
    def __init__(self):
        self._db: Dict[int, dict] = {}
        self._next_id = 0

    def add(self, username: str) -> int:
        uid = self._next_id
        self._db[uid] = {'name': username, 'active': True, 'ctr': 0}
        self._next_id += 1
        return uid

    def exists(self, uid: int) -> bool:
        return uid in self._db

    def is_active(self, uid: int) -> bool:
        return self._db[uid]['active']

    def username(self, uid: int) -> str:
        return self._db[uid]['name']

    def counter(self, uid: int) -> int:
        return self._db[uid]['ctr']

    def inc(self, uid: int, by: int):
        self._db[uid]['ctr'] += by

    def deactivate(self, uid: int):
        self._db[uid]['active'] = False


def _cid(hash_secret: bytes, uid: int, params: Parameters) -> bytes:
    return _hn(hash_secret + uid.to_bytes(USER_BYTES, 'big'), params)

def _cid_star(uid: int, cid: bytes, params: Parameters) -> bytes:
    return _hn(cid + uid.to_bytes(USER_BYTES, 'big'), params)

def _pi(wots_pk: bytes, cid: bytes, params: Parameters) -> bytes:
    return _hn(wots_pk + cid, params)

def _tau(wots_pk: bytes, pi: bytes, uid: int, params: Parameters) -> bytes:
    return _hn(wots_pk + pi + uid.to_bytes(USER_BYTES, 'big'), params)

def _wots_key(seed_u: bytes, wots_seed: bytes, params: Parameters) -> bytes:
    return _hn(seed_u + wots_seed, params)

def _cert_msg(wots_pk: bytes, zeta: bytes, tau: bytes) -> bytes:
    return wots_pk + zeta + tau

def _adrs() -> ADRS:
    a = ADRS()
    a.set_layer(0)
    a.set_tree(0)
    a.set_type(AdrsType.WOTS_HASH)
    a.set_key_pair(0)
    return a


def keygen_manager(params: Parameters) -> Tuple[tuple, tuple]:
    spx_sk, spx_pk = spx_keygen(params)
    hash_secret = secrets.token_bytes(params.n)
    aes_key = secrets.token_bytes(params.n)
    msk = (spx_sk, hash_secret, aes_key)
    return spx_pk, msk


def keygen_user(params: Parameters) -> bytes:
    return secrets.token_bytes(params.n)


def join(msk: tuple, username: str, ml: MembershipList, params: Parameters) -> Tuple[int, bytes]:
    _, hash_secret, _ = msk
    uid = ml.add(username)
    cid = _cid(hash_secret, uid, params)
    cs = _cid_star(uid, cid, params)
    return uid, cs


def csr(seed_u: bytes, count: int, params: Parameters) -> Tuple[List[bytes], List[bytes]]:
    pks, seeds = [], []
    for _ in range(count):
        ws = secrets.token_bytes(params.n)
        key = _wots_key(seed_u, ws, params)
        pk = wots_gen_pk(key, ws, _adrs(), params)
        pks.append(pk)
        seeds.append(ws)
    return pks, seeds


def gen_cert(msk: tuple, uid: int, cs: bytes, wots_pks: List[bytes],
             ml: MembershipList, params: Parameters) -> List[Certificate]:
    spx_sk, hash_secret, aes_key = msk

    if not ml.exists(uid) or not ml.is_active(uid):
        raise ValueError("user not found or revoked")

    cid = _cid(hash_secret, uid, params)
    if cs != _cid_star(uid, cid, params):
        raise ValueError("cid_star mismatch")

    ctr = ml.counter(uid)
    certs = []
    for i, wots_pk in enumerate(wots_pks):
        plaintext = uid.to_bytes(USER_BYTES, 'big') + (ctr + i).to_bytes(USER_BYTES, 'big')
        zeta = _encrypt(aes_key, plaintext)
        pi = _pi(wots_pk, cid, params)
        tau_val = _tau(wots_pk, pi, uid, params)
        sig = spx_sign(_cert_msg(wots_pk, zeta, tau_val), spx_sk, params)
        certs.append(Certificate(zeta=zeta, pi=pi, spx_sig=sig))

    ml.inc(uid, len(wots_pks))
    return certs


def sign(message: bytes, seed_u: bytes, uid: int,
         wots_seed: bytes, cert: Certificate, params: Parameters) -> GroupSignature:
    key = _wots_key(seed_u, wots_seed, params)
    digest = _hn(message, params)
    wots_sig = wots_sign(digest, key, wots_seed, _adrs(), params)
    wots_pk = wots_pk_from_sig(wots_sig, digest, wots_seed, _adrs(), params)
    tau_val = _tau(wots_pk, cert.pi, uid, params)
    return GroupSignature(
        wots_sig=wots_sig,
        wots_seed=wots_seed,
        zeta=cert.zeta,
        spx_sig=cert.spx_sig,
        tau=tau_val,
    )


def verify(message: bytes, sig: GroupSignature,
           revoked: Set[bytes], mpk: tuple, params: Parameters) -> bool:
    if sig.zeta in revoked:
        return False
    digest = _hn(message, params)
    wots_pk = wots_pk_from_sig(sig.wots_sig, digest, sig.wots_seed, _adrs(), params)
    return spx_verify(_cert_msg(wots_pk, sig.zeta, sig.tau), sig.spx_sig, mpk, params)


def open_sig(msk: tuple, sig: GroupSignature, message: bytes,
             ml: MembershipList, params: Parameters) -> Tuple[int, str, bytes]:
    _, hash_secret, aes_key = msk
    plain = _decrypt(aes_key, sig.zeta)
    uid = int.from_bytes(plain[:USER_BYTES], 'big')
    if not ml.exists(uid):
        raise ValueError("unknown user")
    digest = _hn(message, params)
    wots_pk = wots_pk_from_sig(sig.wots_sig, digest, sig.wots_seed, _adrs(), params)
    cid = _cid(hash_secret, uid, params)
    pi = _pi(wots_pk, cid, params)
    return uid, ml.username(uid), pi


def judge(sig: GroupSignature, message: bytes, uid: int, pi: bytes, params: Parameters) -> bool:
    digest = _hn(message, params)
    wots_pk = wots_pk_from_sig(sig.wots_sig, digest, sig.wots_seed, _adrs(), params)
    return sig.tau == _tau(wots_pk, pi, uid, params)


def revoke(msk: tuple, uids: List[int], ml: MembershipList,
           revoked: Set[bytes], params: Parameters):
    _, _, aes_key = msk
    for uid in uids:
        if not ml.exists(uid) or not ml.is_active(uid):
            continue
        ctr = ml.counter(uid)
        for i in range(ctr):
            plaintext = uid.to_bytes(USER_BYTES, 'big') + i.to_bytes(USER_BYTES, 'big')
            revoked.add(_encrypt(aes_key, plaintext))
        ml.deactivate(uid)
