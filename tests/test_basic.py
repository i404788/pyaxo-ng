import pytest
from pyaxo_ng import AxolotlConversation
from Crypto.Random import get_random_bytes


def test_mkey():
    mkey = get_random_bytes(32)
    a = AxolotlConversation.new_from_mkey(mkey)
    b = AxolotlConversation.new_from_mkey(mkey, a.ks['DHRs'])

    o = b'Test msg'
    c = a.encrypt(o)
    p = b.decrypt(c)
    
    c2 = a.encrypt(o)
    p2 = b.decrypt(c2)

    assert p == o and p2 == o
    assert c != o and c != p and c2 != p2 and c2 != o
    
    assert a.ks['RK'] == b.ks['RK'] and type(a.ks['RK']) == bytes


def test_recipient_sends_first():
    mkey = get_random_bytes(32)
    a = AxolotlConversation.new_from_mkey(mkey)
    b = AxolotlConversation.new_from_mkey(mkey, a.ks['DHRs'])

    o = b'Test msg'
    c = b.encrypt(o)
    p = a.decrypt(c)
    
    c2 = b.encrypt(o)
    p2 = a.decrypt(c2)

    assert p == o and p2 == o
    assert c != o and c != p and c2 != p2 and c2 != o
    
    assert a.ks['RK'] == b.ks['RK'] and type(a.ks['RK']) == bytes 

def test_out_of_order():
    mkey = get_random_bytes(32)
    a = AxolotlConversation.new_from_mkey(mkey)
    b = AxolotlConversation.new_from_mkey(mkey, a.ks['DHRs'])

    o = b'Test msg'
    c1 = a.encrypt(o)
    c2 = a.encrypt(o + b'0')
    c3 = a.encrypt(o + b'1')
    c4 = a.encrypt(o + b'2')

    p4 = b.decrypt(c4)
    p3 = b.decrypt(c3)
    p2 = b.decrypt(c2)
    p1 = b.decrypt(c1)
    assert p1 == o
    assert p2 == o + b'0'
    assert p3 == o + b'1'
    assert p4 == o + b'2'

def test_unidir_comm():
    mkey = get_random_bytes(32)
    a = AxolotlConversation.new_from_mkey(mkey)
    b = AxolotlConversation.new_from_mkey(mkey, a.ks['DHRs'])
    
    o = b'Test msg'
    
    # Simulate unidirectional communication issue (a can only receive for long time)
    ca1 = a.encrypt(o)
    cb1 = b.encrypt(o)
    cb2 = b.encrypt(o)
    cb3 = b.encrypt(o)
    assert o == a.decrypt(cb1)
    ca2 = a.encrypt(o)
    assert o == a.decrypt(cb2)
    ca3 = a.encrypt(o)
    assert o == a.decrypt(cb3)
    ca4 = a.encrypt(o)
    cb4 = b.encrypt(o)
    assert o == a.decrypt(cb4)

    # Comm restored, but messages out-of-order
    assert o == b.decrypt(ca3)
    assert o == b.decrypt(ca4)
    assert o == b.decrypt(ca1)
    assert o == b.decrypt(ca2)


def test_root_skipped_mk():
    mkey = get_random_bytes(32)
    a = AxolotlConversation.new_from_mkey(mkey)
    b = AxolotlConversation.new_from_mkey(mkey, a.ks['DHRs'])
    
    o = b'Test msg'
    
    _ = a.encrypt(o)        # ACHs1-1 (skipped)
    _ = a.encrypt(o)        # ACHs1-2 (skipped)
    _ = a.encrypt(o)        # ACHs1-3 (skipped)
    _ = a.encrypt(o)        # ACHs1-4 (skipped)
    _ = a.encrypt(o)        # ACHs1-5 (skipped)
    _ = a.encrypt(o)        # ACHs1-6 (skipped)
    _ = a.encrypt(o)        # ACHs1-7 (skipped)
    ca2 = a.encrypt(o)      # ACHs1-8 (recovered last)
    # pa1 = b.decrypt(ca1)    # ACHr1-1
    cb1 = b.encrypt(o)      # BCHs1-1
    pb1 = a.decrypt(cb1)    # BCHr1-1
    ca3 = a.encrypt(o)      # ACHs2-1
    pa3 = b.decrypt(ca3)    # ACHr2-1
    cb2 = b.encrypt(o)      # BCHs2-1
    pb2 = a.decrypt(cb2)    # BCHr2-1
    ca4 = a.encrypt(o)      # ACHs3-1
    pa4 = b.decrypt(ca4)    # ACHr3-1

    # Found forgotten message
    pa2 = b.decrypt(ca2)
    assert pa2 == o



