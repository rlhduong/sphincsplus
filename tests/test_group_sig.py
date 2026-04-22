import pytest
from src.parameters import Parameters
from src.group_sig import (
    keygen_manager, keygen_user, join, csr, gen_cert,
    sign, verify, open_sig, judge, revoke,
    MembershipList,
)


@pytest.fixture(scope='module')
def params():
    return Parameters.get_paramset("sphincs-sha2-128s")


@pytest.fixture(scope='module')
def setup(params):
    mpk, msk = keygen_manager(params)
    ml = MembershipList()
    seed_u = keygen_user(params)
    uid, cs = join(msk, "alice", ml, params)
    wots_pks, wots_seeds = csr(seed_u, 3, params)
    certs = gen_cert(msk, uid, cs, wots_pks, ml, params)
    return mpk, msk, ml, seed_u, uid, wots_seeds, certs


def test_sign_and_verify(setup, params):
    mpk, msk, ml, seed_u, uid, wots_seeds, certs = setup
    msg = b"test message"
    sig = sign(msg, seed_u, uid, wots_seeds[0], certs[0], params)
    assert verify(msg, sig, set(), mpk, params)


def test_wrong_message_fails(setup, params):
    mpk, _, _, seed_u, uid, wots_seeds, certs = setup
    msg = b"original"
    sig = sign(msg, seed_u, uid, wots_seeds[1], certs[1], params)
    assert not verify(b"tampered", sig, set(), mpk, params)


def test_revocation(setup, params):
    mpk, msk, ml, seed_u, uid, wots_seeds, certs = setup
    msg = b"revoke test"

    # sign before revocation - should work
    sig = sign(msg, seed_u, uid, wots_seeds[2], certs[2], params)
    revoked: set = set()
    assert verify(msg, sig, revoked, mpk, params)

    # revoke and check signature is now rejected
    revoke(msk, [uid], ml, revoked, params)
    assert not verify(msg, sig, revoked, mpk, params)


def test_open_and_judge(params):
    mpk, msk = keygen_manager(params)
    ml = MembershipList()
    seed_u = keygen_user(params)
    uid, cs = join(msk, "bob", ml, params)
    wots_pks, wots_seeds = csr(seed_u, 1, params)
    certs = gen_cert(msk, uid, cs, wots_pks, ml, params)

    msg = b"open me"
    sig = sign(msg, seed_u, uid, wots_seeds[0], certs[0], params)

    opened_uid, username, pi = open_sig(msk, sig, msg, ml, params)
    assert opened_uid == uid
    assert username == "bob"
    assert judge(sig, msg, uid, pi, params)


def test_invalid_cid_star_rejected(params):
    _, msk = keygen_manager(params)
    ml = MembershipList()
    seed_u = keygen_user(params)
    uid, _ = join(msk, "eve", ml, params)
    wots_pks, _ = csr(seed_u, 1, params)

    bad_cs = b'\x00' * params.n
    with pytest.raises(ValueError):
        gen_cert(msk, uid, bad_cs, wots_pks, ml, params)


def test_two_users_independent(params):
    mpk, msk = keygen_manager(params)
    ml = MembershipList()

    seed_a = keygen_user(params)
    seed_b = keygen_user(params)
    uid_a, cs_a = join(msk, "alice", ml, params)
    uid_b, cs_b = join(msk, "bob", ml, params)

    pks_a, seeds_a = csr(seed_a, 1, params)
    pks_b, seeds_b = csr(seed_b, 1, params)
    certs_a = gen_cert(msk, uid_a, cs_a, pks_a, ml, params)
    certs_b = gen_cert(msk, uid_b, cs_b, pks_b, ml, params)

    msg = b"shared message"
    sig_a = sign(msg, seed_a, uid_a, seeds_a[0], certs_a[0], params)
    sig_b = sign(msg, seed_b, uid_b, seeds_b[0], certs_b[0], params)

    revoked = set()
    assert verify(msg, sig_a, revoked, mpk, params)
    assert verify(msg, sig_b, revoked, mpk, params)

    # revoke alice, bob's sig still valid
    revoke(msk, [uid_a], ml, revoked, params)
    assert not verify(msg, sig_a, revoked, mpk, params)
    assert verify(msg, sig_b, revoked, mpk, params)
