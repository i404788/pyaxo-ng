import pytest

from pyaxo_ng import generate_keypair


@pytest.fixture()
def keypair():
    return generate_keypair()

def test_keypair_different_values(keypair):
    assert keypair[0] != keypair[1]


def test_keypair_bytes(keypair):
    assert isinstance(keypair[0], bytes) and isinstance(keypair[1], bytes)
