import pytest
from pyaxo_ng import AxolotlConversation


def test_basic_x3dh():
    rKeys, rResolve = AxolotlConversation.new_from_x3dh(mode=False) # Bob/Initiator
    oKeys, oResolve = AxolotlConversation.new_from_x3dh(mode=True) # Alice/Recipient

    rConv = rResolve(*oKeys)
    oConv = oResolve(*rKeys)
    
    assert rConv.ks['RK'] == oConv.ks['RK'] and type(rConv.ks['RK']) == bytes
    assert oConv.ks['DHRr'] == rConv.ks['DHRs'] and type(oConv.ks['DHRr']) == bytes 

    o = b'Test msg'
    c = rConv.encrypt(o)
    p = oConv.decrypt(c)
    
    c2 = oConv.encrypt(o)
    p2 = rConv.decrypt(c2)

    assert p == o and p2 == o
    assert c != o and c != p and c2 != p2 and c2 != o
    
    assert rConv.ks['RK'] == oConv.ks['RK'] and type(rConv.ks['RK']) == bytes 

def test_out_of_order():
    rKeys, rResolve = AxolotlConversation.new_from_x3dh(mode=False) # Bob/Initiator
    oKeys, oResolve = AxolotlConversation.new_from_x3dh(mode=True) # Alice/Recipient

    rConv = rResolve(*oKeys)
    oConv = oResolve(*rKeys)

    o = b'Test msg'
    c1 = rConv.encrypt(o)
    c2 = rConv.encrypt(o + b'0')
    c3 = rConv.encrypt(o + b'1')
    c4 = rConv.encrypt(o + b'2')

    p4 = oConv.decrypt(c4)
    p3 = oConv.decrypt(c3)
    p2 = oConv.decrypt(c2)
    p1 = oConv.decrypt(c1)
    assert p1 == o
    assert p2 == o + b'0'
    assert p3 == o + b'1'
    assert p4 == o + b'2'

def test_recipient_sends_first():
    rKeys, rResolve = AxolotlConversation.new_from_x3dh(mode=False) # Bob/Initiator
    oKeys, oResolve = AxolotlConversation.new_from_x3dh(mode=True) # Alice/Recipient

    rConv = rResolve(*oKeys)
    oConv = oResolve(*rKeys)

    o = b'Test msg'
    c = oConv.encrypt(o)
    p = rConv.decrypt(c)
    assert p == o
    assert c != o and c != p
