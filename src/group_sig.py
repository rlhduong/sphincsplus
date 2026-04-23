"""Group signature scheme built on SPHINCS+ and WOTS+.

Implements the five group-signature operations — **Setup** (manager and user
keygen), **Join** (issue membership credentials), **Sign** (produce an
anonymous group signature), **Verify** (check a group signature without
learning who signed), and **Open** / **Judge** / **Revoke** (manager-side
de-anonymisation and membership revocation).

A 4-round Feistel cipher encrypts ``(uid, counter)`` into a ``zeta`` token
that binds each one-time WOTS+ key to its owner without revealing the
identity to verifiers. The manager can decrypt ``zeta`` to trace a
signature back to the signer.
"""

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


def _f(key: bytes, data: bytes, r: int) -> bytes:
    """Single-round Feistel PRF: ``SHA-256(key || round || data)`` truncated to 8 bytes.

    Args:
        key: Symmetric key (the manager's ``aes_key``).
        data: Half-block being processed.
        r: Feistel round index (0-3).

    Returns:
        8-byte pseudorandom output.
    """
    return hashlib.sha256(key + r.to_bytes(1, "big") + data).digest()[:8]


def _encrypt(key: bytes, block: bytes) -> bytes:
    """Encrypt a 16-byte ``(uid || counter)`` block with a 4-round Feistel cipher.

    Args:
        key: Symmetric key.
        block: 16-byte plaintext (``USER_BYTES`` uid + ``USER_BYTES`` counter).

    Returns:
        16-byte ciphertext ``zeta``.
    """
    L, R = block[:8], block[8:]
    for i in range(4):
        L, R = R, bytes(a ^ b for a, b in zip(L, _f(key, R, i)))
    return L + R


def _decrypt(key: bytes, block: bytes) -> bytes:
    """Decrypt a 16-byte ``zeta`` back to ``(uid || counter)``.

    Args:
        key: Symmetric key (same as used for encryption).
        block: 16-byte ciphertext.

    Returns:
        16-byte plaintext.
    """
    L, R = block[:8], block[8:]
    for i in range(3, -1, -1):
        R, L = L, bytes(a ^ b for a, b in zip(R, _f(key, L, i)))
    return L + R


def _hn(data: bytes, params: Parameters) -> bytes:
    """Parameter-aware ``n``-byte hash helper (SHA-256, SHA-512, or SHAKE-256).

    Args:
        data: Arbitrary-length input.
        params: Selects the hash function and output length ``n``.

    Returns:
        ``n``-byte digest.
    """
    if params.hash_fn == "shake":
        return hashlib.shake_256(data).digest(params.n)
    if params.n <= 32:
        return hashlib.sha256(data).digest()[: params.n]
    return hashlib.sha512(data).digest()[: params.n]


@dataclass
class Certificate:
    """Manager-issued credential binding a WOTS+ key to a group member.

    Attributes:
        zeta: Encrypted ``(uid, counter)`` token (16 bytes).
        pi: Membership proof ``H(wots_pk || cid)``.
        spx_sig: SPHINCS+ signature over ``wots_pk || zeta || tau``.
    """

    zeta: bytes
    pi: bytes
    spx_sig: bytes


@dataclass
class GroupSignature:
    """Anonymous group signature on a message.

    Attributes:
        wots_sig: WOTS+ signature on ``H(message)``.
        wots_seed: Public per-key randomness needed to recover the WOTS+ pk.
        zeta: Encrypted identity token carried from the certificate.
        spx_sig: SPHINCS+ signature certifying the WOTS+ key.
        tau: Binding tag ``H(wots_pk || pi || uid)`` linking cert to signer.
    """

    wots_sig: bytes
    wots_seed: bytes
    zeta: bytes
    spx_sig: bytes
    tau: bytes


class MembershipList:
    """In-memory registry of group members maintained by the manager.

    Each member is assigned a sequential ``uid`` and tracked with a username,
    active/revoked flag, and a monotonic counter incremented every time new
    WOTS+ certificates are issued (so ``zeta`` values are unique).
    """

    def __init__(self):
        """Create an empty membership list."""
        self._db: Dict[int, dict] = {}
        self._next_id = 0

    def add(self, username: str) -> int:
        """Register a new member and return their ``uid``."""
        uid = self._next_id
        self._db[uid] = {"name": username, "active": True, "ctr": 0}
        self._next_id += 1
        return uid

    def exists(self, uid: int) -> bool:
        """Return ``True`` if ``uid`` has ever been registered."""
        return uid in self._db

    def is_active(self, uid: int) -> bool:
        """Return ``True`` if the member has not been revoked."""
        return self._db[uid]["active"]

    def username(self, uid: int) -> str:
        """Return the human-readable name associated with ``uid``."""
        return self._db[uid]["name"]

    def counter(self, uid: int) -> int:
        """Return the current certificate counter for ``uid``."""
        return self._db[uid]["ctr"]

    def inc(self, uid: int, by: int):
        """Advance the certificate counter by ``by`` (called after issuing certs)."""
        self._db[uid]["ctr"] += by

    def deactivate(self, uid: int):
        """Mark the member as revoked (all their ``zeta`` tokens become invalid)."""
        self._db[uid]["active"] = False


def _cid(hash_secret: bytes, uid: int, params: Parameters) -> bytes:
    """Compute the secret credential id: ``H(hash_secret || uid)``."""
    return _hn(hash_secret + uid.to_bytes(USER_BYTES, "big"), params)


def _cid_star(uid: int, cid: bytes, params: Parameters) -> bytes:
    """Compute the public credential check: ``H(cid || uid)``."""
    return _hn(cid + uid.to_bytes(USER_BYTES, "big"), params)


def _pi(wots_pk: bytes, cid: bytes, params: Parameters) -> bytes:
    """Membership proof binding a WOTS+ key to a credential: ``H(wots_pk || cid)``."""
    return _hn(wots_pk + cid, params)


def _tau(wots_pk: bytes, pi: bytes, uid: int, params: Parameters) -> bytes:
    """Binding tag used in certificate and judge: ``H(wots_pk || pi || uid)``."""
    return _hn(wots_pk + pi + uid.to_bytes(USER_BYTES, "big"), params)


def _wots_key(seed_u: bytes, wots_seed: bytes, params: Parameters) -> bytes:
    """Derive the user's WOTS+ secret key from their seed and the per-key randomness."""
    return _hn(seed_u + wots_seed, params)


def _cert_msg(wots_pk: bytes, zeta: bytes, tau: bytes) -> bytes:
    """Build the message that the manager's SPHINCS+ key signs inside a certificate."""
    return wots_pk + zeta + tau


def _adrs() -> ADRS:
    """Return a fresh WOTS_HASH address at ``(layer=0, tree=0, key_pair=0)``."""
    a = ADRS()
    a.set_layer(0)
    a.set_tree(0)
    a.set_type(AdrsType.WOTS_HASH)
    a.set_key_pair(0)
    return a


def keygen_manager(params: Parameters) -> Tuple[tuple, tuple]:
    """Generate the group manager's key pair (``mpk``, ``msk``).

    Generates a SPHINCS+ key pair for signing certificates, a random
    ``hash_secret`` used to derive credential ids, and an ``aes_key`` used
    to encrypt ``(uid, counter)`` into ``zeta`` tokens.

    Args:
        params: Parameter set.

    Returns:
        ``(mpk, msk)`` where ``mpk = spx_pk`` and
        ``msk = (spx_sk, hash_secret, aes_key)``.
    """
    spx_sk, spx_pk = spx_keygen(params)
    hash_secret = secrets.token_bytes(params.n)
    aes_key = secrets.token_bytes(params.n)
    msk = (spx_sk, hash_secret, aes_key)
    return spx_pk, msk


def keygen_user(params: Parameters) -> bytes:
    """Generate a user's long-term secret seed (``seed_u``).

    Args:
        params: Parameter set (only ``n`` is used for the byte length).

    Returns:
        ``n``-byte random seed.
    """
    return secrets.token_bytes(params.n)


def join(
    msk: tuple, username: str, ml: MembershipList, params: Parameters
) -> Tuple[int, bytes]:
    """Register a new user in the group and return ``(uid, cid_star)``.

    The manager computes a secret ``cid`` and a publicly-verifiable
    ``cid_star`` that the user will present when requesting certificates.

    Args:
        msk: Manager secret key tuple.
        username: Human-readable name for the new member.
        ml: Membership list to register in.
        params: Parameter set.

    Returns:
        ``(uid, cid_star)`` — the user's numeric id and their credential
        check value.
    """
    _, hash_secret, _ = msk
    uid = ml.add(username)
    cid = _cid(hash_secret, uid, params)
    cs = _cid_star(uid, cid, params)
    return uid, cs


def csr(
    seed_u: bytes, count: int, params: Parameters
) -> Tuple[List[bytes], List[bytes]]:
    """User-side Certificate Signing Request: generate ``count`` WOTS+ key pairs.

    Each key pair uses fresh randomness ``wots_seed``; the secret key is
    derived deterministically from ``seed_u + wots_seed``. The returned
    public keys are sent to the manager for certification.

    Args:
        seed_u: The user's long-term secret seed.
        count: Number of one-time key pairs to generate.
        params: Parameter set.

    Returns:
        ``(wots_pks, wots_seeds)`` — lists of length ``count``.
    """
    pks, seeds = [], []
    for _ in range(count):
        ws = secrets.token_bytes(params.n)
        key = _wots_key(seed_u, ws, params)
        pk = wots_gen_pk(key, ws, _adrs(), params)
        pks.append(pk)
        seeds.append(ws)
    return pks, seeds


def gen_cert(
    msk: tuple,
    uid: int,
    cs: bytes,
    wots_pks: List[bytes],
    ml: MembershipList,
    params: Parameters,
) -> List[Certificate]:
    """Manager-side: issue one ``Certificate`` per WOTS+ public key.

    Validates the user's ``cid_star``, encrypts ``(uid, counter)`` into
    ``zeta``, computes ``pi`` and ``tau``, and signs the bundle with the
    manager's SPHINCS+ secret key. The membership counter is advanced by the
    number of certificates issued.

    Args:
        msk: Manager secret key tuple ``(spx_sk, hash_secret, aes_key)``.
        uid: User id to certify.
        cs: ``cid_star`` presented by the user (checked against the expected value).
        wots_pks: List of WOTS+ public keys to certify.
        ml: Membership list (used for existence/revocation check and counter).
        params: Parameter set.

    Returns:
        One ``Certificate`` per entry in ``wots_pks``.

    Raises:
        ValueError: If the user is unknown/revoked or ``cid_star`` mismatches.
    """
    spx_sk, hash_secret, aes_key = msk

    if not ml.exists(uid) or not ml.is_active(uid):
        raise ValueError("user not found or revoked")

    cid = _cid(hash_secret, uid, params)
    if cs != _cid_star(uid, cid, params):
        raise ValueError("cid_star mismatch")

    ctr = ml.counter(uid)
    certs = []
    for i, wots_pk in enumerate(wots_pks):
        plaintext = uid.to_bytes(USER_BYTES, "big") + (ctr + i).to_bytes(
            USER_BYTES, "big"
        )
        zeta = _encrypt(aes_key, plaintext)
        pi = _pi(wots_pk, cid, params)
        tau_val = _tau(wots_pk, pi, uid, params)
        sig = spx_sign(_cert_msg(wots_pk, zeta, tau_val), spx_sk, params)
        certs.append(Certificate(zeta=zeta, pi=pi, spx_sig=sig))

    ml.inc(uid, len(wots_pks))
    return certs


def sign(
    message: bytes,
    seed_u: bytes,
    uid: int,
    wots_seed: bytes,
    cert: Certificate,
    params: Parameters,
) -> GroupSignature:
    """Produce an anonymous group signature on ``message``.

    The user re-derives their WOTS+ secret key from ``seed_u + wots_seed``,
    signs ``H(message)``, recovers the WOTS+ public key from the signature
    to recompute ``tau``, and bundles everything into a ``GroupSignature``.

    Args:
        message: Arbitrary message bytes.
        seed_u: The user's long-term secret seed.
        uid: User id (needed to compute ``tau``).
        wots_seed: Per-key randomness (from ``csr``).
        cert: The ``Certificate`` that certifies this WOTS+ key.
        params: Parameter set.

    Returns:
        A ``GroupSignature`` that any verifier can check anonymously.
    """
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


def verify(
    message: bytes,
    sig: GroupSignature,
    revoked: Set[bytes],
    mpk: tuple,
    params: Parameters,
) -> bool:
    """Verify a group signature anonymously.

    Checks the ``zeta`` token against the revocation set, recovers the WOTS+
    public key from the signature, and verifies the manager's SPHINCS+
    certificate over ``wots_pk || zeta || tau``.

    Args:
        message: Message the signature is allegedly over.
        sig: ``GroupSignature`` to verify.
        revoked: Set of revoked ``zeta`` tokens.
        mpk: Manager public key (``spx_pk``).
        params: Parameter set.

    Returns:
        ``True`` iff the signature is valid and not revoked.
    """
    if sig.zeta in revoked:
        return False
    digest = _hn(message, params)
    wots_pk = wots_pk_from_sig(sig.wots_sig, digest, sig.wots_seed, _adrs(), params)
    return spx_verify(_cert_msg(wots_pk, sig.zeta, sig.tau), sig.spx_sig, mpk, params)


def open_sig(
    msk: tuple,
    sig: GroupSignature,
    message: bytes,
    ml: MembershipList,
    params: Parameters,
) -> Tuple[int, str, bytes]:
    """Manager-only: de-anonymise a group signature.

    Decrypts ``zeta`` to recover the signer's ``uid``, looks up their
    username, and recomputes ``pi`` so it can be presented to a judge.

    Args:
        msk: Manager secret key.
        sig: The group signature to open.
        message: The original signed message.
        ml: Membership list.
        params: Parameter set.

    Returns:
        ``(uid, username, pi)`` — the signer's identity and membership proof.

    Raises:
        ValueError: If the decrypted ``uid`` is not in the membership list.
    """
    _, hash_secret, aes_key = msk
    plain = _decrypt(aes_key, sig.zeta)
    uid = int.from_bytes(plain[:USER_BYTES], "big")
    if not ml.exists(uid):
        raise ValueError("unknown user")
    digest = _hn(message, params)
    wots_pk = wots_pk_from_sig(sig.wots_sig, digest, sig.wots_seed, _adrs(), params)
    cid = _cid(hash_secret, uid, params)
    pi = _pi(wots_pk, cid, params)
    return uid, ml.username(uid), pi


def judge(
    sig: GroupSignature, message: bytes, uid: int, pi: bytes, params: Parameters
) -> bool:
    """Publicly verify that ``sig`` was indeed produced by ``uid``.

    Recomputes ``tau`` from the recovered WOTS+ public key, the supplied
    ``pi``, and ``uid``, then checks it against ``sig.tau``.

    Args:
        sig: The group signature under dispute.
        message: The original message.
        uid: Claimed signer id (supplied by the opener).
        pi: Membership proof for ``uid`` (supplied by the opener).
        params: Parameter set.

    Returns:
        ``True`` iff the binding tag matches, confirming attribution.
    """
    digest = _hn(message, params)
    wots_pk = wots_pk_from_sig(sig.wots_sig, digest, sig.wots_seed, _adrs(), params)
    return sig.tau == _tau(wots_pk, pi, uid, params)


def revoke(
    msk: tuple,
    uids: List[int],
    ml: MembershipList,
    revoked: Set[bytes],
    params: Parameters,
):
    """Revoke one or more members by adding all their ``zeta`` tokens to the revocation set.

    For each uid the function re-encrypts every ``(uid, i)`` pair for
    ``i`` in ``[0, counter)`` and inserts the resulting ``zeta`` values into
    ``revoked``. The member is then marked inactive in the membership list
    so no further certificates can be issued.

    Args:
        msk: Manager secret key (only ``aes_key`` is used).
        uids: List of user ids to revoke.
        ml: Membership list.
        revoked: Mutable set of revoked ``zeta`` tokens (updated in place).
        params: Parameter set.
    """
    _, _, aes_key = msk
    for uid in uids:
        if not ml.exists(uid) or not ml.is_active(uid):
            continue
        ctr = ml.counter(uid)
        for i in range(ctr):
            plaintext = uid.to_bytes(USER_BYTES, "big") + i.to_bytes(USER_BYTES, "big")
            revoked.add(_encrypt(aes_key, plaintext))
        ml.deactivate(uid)
