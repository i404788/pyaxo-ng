import pytest
from pyaxo_ng import AxolotlConversation


def test_basic_x3dh():
    rKeys, rResolve = AxolotlConversation.new_from_x3dh(mode=False) # Bob/Initiator
    oKeys, oResolve = AxolotlConversation.new_from_x3dh(mode=True) # Alice/Recipient

    rConv = rResolve(*oKeys)
    oConv = oResolve(*rKeys)

    o = b'Test msg'
    c = rConv.encrypt(o)
    p = oConv.decrypt(c)
    assert p == o
    assert c != o and c != p
