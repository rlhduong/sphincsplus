"""Full SPHINCS+ end-to-end test: keygen, sign, verify, and reject tampered inputs."""

import pytest
import random
from src.sphincs import *


@pytest.fixture
def params() -> Parameters:
    """``sphincs-sha2-128s`` parameter set."""
    return Parameters.get_paramset("sphincs-sha2-128s")


def test_sphincs(params: Parameters):
    """Valid signature passes; wrong message and corrupted signature fail."""
    sk, pk = spx_keygen(params)

    msg = b"Hello COMP3454!"
    sig = spx_sign(msg, sk, params)
    assert spx_verify(msg, sig, pk, params)
    assert not spx_verify(b"Hello COMP6453!", sig, pk, params)
    assert not spx_verify(msg, sig[:-1] + b"\x00", pk, params)
