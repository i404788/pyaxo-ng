import pytest

from pyaxo_ng import generate_keypair

from . import utils


@pytest.fixture()
def a_identity_keys():
    return generate_keypair()


@pytest.fixture()
def b_identity_keys():
    return generate_keypair()


@pytest.fixture()
def c_identity_keys():
    return generate_keypair()


@pytest.fixture()
def a_handshake_keys():
    return generate_keypair()


@pytest.fixture()
def b_handshake_keys():
    return generate_keypair()


@pytest.fixture()
def c_handshake_keys():
    return generate_keypair()


@pytest.fixture()
def a_ratchet_keys():
    return generate_keypair()


@pytest.fixture()
def b_ratchet_keys():
    return generate_keypair()


@pytest.fixture()
def c_ratchet_keys():
    return generate_keypair()

