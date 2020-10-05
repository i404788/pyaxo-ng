import os
import sys
import struct
from typing import NamedTuple
from collections import namedtuple
from functools import wraps
from getpass import getpass
from threading import Lock
from time import time
import base64

from nacl.public import PrivateKey, PublicKey, Box

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import HMAC, SHA512, SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from diskcache import Cache

ALICE_MODE = True
BOB_MODE = False

SALTS = {'RK': b'\x00',
         'HK': {ALICE_MODE: b'\x01', BOB_MODE: b'\x02'},
         'NHK': {ALICE_MODE: b'\x03', BOB_MODE: b'\x04'},
         'CK': {ALICE_MODE: b'\x05', BOB_MODE: b'\x06'},
         'CONVid': b'\x07'}

HEADER_LEN = 84
HEADER_PAD_NUM_LEN = 1
HEADER_COUNT_NUM_LEN = 4

class Keypair(NamedTuple):
    priv: bytes
    pub: bytes

class SkippedMessageKey(NamedTuple):
    mk: bytes
    hk: bytes
    timestamp: int

def sync(f):
    @wraps(f)
    def synced_f(self, *args, **kwargs):
        with self.lock:
            return f(self, *args, **kwargs)
    return synced_f


# TODO: create DHI in manager (used for x3dh/fingerprint, should be outside of conv)
class AxolotlConversation:
    """
    Implementation of DoubleRatchet w/ header encryption
    Specifics: AES128-SIV, HKDF(SHA512), HMAC(SHA512)

    DHRs: DH Ratchet key pair (the "sending" or "self" ratchet key)
    DHRr: DH Ratchet public key (the "received" or "remote" key)
    RK: 32-byte Root Keys
    CKs, CKr: 32-byte Chain Keys for sending and receiving
    Ns, Nr: Message numbers for sending and receiving
    PN: Number of messages in previous sending chain
    MKSKIPPED: Dictionary of skipped-over message keys, indexed by ratchet public key and message number. Raises an exception if too many elements are stored.

    HKs, HKr: Header keys for sending and receiving
    NHKs, NHKr: Next header keys for sending and receiving

    CONVid: Hash-Identifier for this particular conversation based on the initial shared key

    Mode: Bob = initiator, Alice = recipient (note: this is reverse of whats used in spec)
        - Bob generates DHR, while Alice requires Bob's DHRs to start the ratchet
        - Changes salts for Header Keys and Chain Keys
    """
    def __init__(self, keys, mode, staged_hk_mk=None):
        self.lock = Lock()
        self.ks = keys
        self.mode = mode
        # TODO: add store_time to staged_hk_mk
        # TODO: limit amount of skipped keys
        self.staged_hk_mk = staged_hk_mk or dict()
        
        self.handshake_key = None
        self.handshake_pkey = None

    @classmethod
    def new_from_x3dh(cls, mode=ALICE_MODE, DHI: Keypair = None, HSK: Keypair = None):
        """
        Create new conversation from X3DH exchange

        Returns
        -------
        (tuple(keys), callable(resolve(keysr)))
        """
        DHR = None if mode else generate_keypair()
        DHI_priv, DHIs = DHI or generate_keypair()
        HSK_priv, HSKs = HSK or generate_keypair() # handshake keys

        def resolve(DHIr, HSKr, DHRr=None):
            mkey = generate_3dh(DHI_priv, HSK_priv,
                                DHIr, HSKr,
                                mode)
            return cls.new_from_mkey(mkey, DHRr, DHR=DHR)

        if not mode:
            return (DHIs, HSKs, DHR.pub), resolve
        else:
            return (DHIs, HSKs), resolve

    @classmethod
    def new_from_mkey(cls, mkey, DHRr = None, DHR: Keypair = None):
        assert len(mkey) == 32, "Bad key length"
        Ns = 0
        Nr = 0
        PNs = 0
        DHRs_priv = None 
        DHRs = None 
        mode = bool(DHRr)
        # TODO: original used kdf(mkey, DH(DHRs, DHRr))
        if mode: # alice mode
            HKs = None
            HKr = kdf(mkey, SALTS['HK'][BOB_MODE])
            CKs = None
            CKr = kdf(mkey, SALTS['CK'][BOB_MODE])
            ratchet_flag = True
        else: # bob mode
            DHRs_priv, DHRs = DHR or generate_keypair()
            HKs = kdf(mkey, SALTS['HK'][BOB_MODE])
            HKr = None
            CKs = kdf(mkey, SALTS['CK'][BOB_MODE])
            CKr = None
            ratchet_flag = False
        RK = kdf(mkey, SALTS['RK'], info=b'RootKey')
        NHKs = kdf(mkey, SALTS['NHK'][mode])
        NHKr = kdf(mkey, SALTS['NHK'][not mode])
        CONVid = kdf(mkey, SALTS['CONVid'])

        keys = { 
                 'RK': RK,
                 'HKs': HKs,
                 'HKr': HKr,
                 'NHKs': NHKs,
                 'NHKr': NHKr,
                 'CKs': CKs,
                 'CKr': CKr,
                 'DHRs_priv': DHRs_priv,
                 'DHRs': DHRs,
                 'DHRr': DHRr,
                 'CONVid': CONVid,
                 'Ns': Ns,
                 'Nr': Nr,
                 'PNs': PNs,
                 'ratchet_flag': ratchet_flag,
                 }
        return cls(keys, mode)

    def _try_skipped_mk(self, msg, pad_length):
        msg1 = msg[:HEADER_LEN-pad_length]
        msg2 = msg[HEADER_LEN:]
        for skipped_mk in self.staged_hk_mk.values():
            try:
                decrypt_symmetric(skipped_mk.hk, msg1)
                body = decrypt_symmetric(skipped_mk.mk, msg2)
            except (ValueError, KeyError):
                pass
            else:
                del self.staged_hk_mk[skipped_mk.mk]
                return body
        return None

    def _stage_skipped_mk(self, hkr, nr, np, ckr):
        timestamp = int(time())
        ckp = ckr
        for i in range(np - nr):
            mk = kdf_ck(ckp, b'0')
            ckp = kdf_ck(ckp, b'1')
            self.staged_hk_mk[mk] = SkippedMessageKey(mk, hkr, timestamp)
        mk = kdf_ck(ckp, b'0')
        ckp = kdf_ck(ckp, b'1')
        return ckp, mk

    @sync
    def encrypt(self, plaintext):
        # Initiating new chain
        if self.ks['ratchet_flag']:
            self.ks['DHRs_priv'], self.ks['DHRs'] = generate_keypair()
            self.ks['HKs'] = self.ks['NHKs']
            # TODO: original uses dh for RK, CK & NHK (also see decrypt())
            self.ks['RK'] = kdf(generate_dh(self.ks['DHRs_priv'], self.ks['DHRr']), self.ks['RK'], info=b'RootKey')
            self.ks['NHKs'] = kdf(self.ks['RK'], SALTS['NHK'][self.mode])
            self.ks['CKs'] = kdf(self.ks['RK'], SALTS['CK'][self.mode])
            self.ks['PNs'] = self.ks['Ns']
            self.ks['Ns'] = 0
            self.ks['ratchet_flag'] = False
        
        # Generate e(header, hk) & e(message, mk)
        mk = kdf_ck(self.ks['CKs'], b'0')
        msg1 = encrypt_symmetric(
            self.ks['HKs'],
            struct.pack('>I', self.ks['Ns']) + struct.pack('>I', self.ks['PNs']) +
            self.ks['DHRs'])
        msg2 = encrypt_symmetric(mk, plaintext)
        pad_length = HEADER_LEN - len(msg1)
        pad = get_random_bytes(pad_length - HEADER_PAD_NUM_LEN) + chr(pad_length).encode()
        msg = msg1 + pad + msg2
        self.ks['Ns'] += 1
        self.ks['CKs'] = kdf_ck(self.ks['CKs'], b'1')
        return msg

    @sync
    def decrypt(self, msg):
        pad = msg[HEADER_LEN-HEADER_PAD_NUM_LEN:HEADER_LEN]
        pad_length = ord(pad)
        msg1 = msg[:HEADER_LEN-pad_length]

        # Check through skipped keys for out-of-order messages
        body = self._try_skipped_mk(msg, pad_length)
        if body and body != '':
            return body

        try:
            # Try decrypt header with current header key
            assert self.ks['HKr']
            header = decrypt_symmetric(self.ks['HKr'], msg1)
        except (ValueError, KeyError, AssertionError):    
            # Try with next header key instead
            try:
                assert not self.ks['ratchet_flag']
                header = decrypt_symmetric(self.ks['NHKr'], msg1)
            except (ValueError, KeyError, AssertionError):
                raise Exception('Undecipherable message')

            # Next header key worked
            # But now we have to add the skipped keys
            Np = struct.unpack('>I', header[:HEADER_COUNT_NUM_LEN])[0]
            PNp = struct.unpack('>I', header[HEADER_COUNT_NUM_LEN:HEADER_COUNT_NUM_LEN*2])[0]
            DHRp = header[HEADER_COUNT_NUM_LEN*2:]
            if self.ks['CKr']:
                self._stage_skipped_mk(self.ks['HKr'], self.ks['Nr'], PNp, self.ks['CKr'])
            HKp = self.ks['NHKr']
            RKp = kdf(generate_dh(self.ks['DHRs_priv'], DHRp), self.ks['RK'], info=b'RootKey')
            NHKp = kdf(RKp, SALTS['NHK'][not self.mode])
            CKp = kdf(RKp, SALTS['CK'][not self.mode])
            CKp, mk = self._stage_skipped_mk(HKp, 0, Np, CKp)
            try:
                body = decrypt_symmetric(mk, msg[HEADER_LEN:])
            except (ValueError, KeyError):
                raise Exception('Undecipherable message')
            self.ks['RK'] = RKp
            self.ks['HKr'] = HKp
            self.ks['NHKr'] = NHKp
            self.ks['DHRr'] = DHRp
            self.ks['DHRs_priv'] = None
            self.ks['DHRs'] = None
            self.ks['ratchet_flag'] = True
        else:
            # HKr decypt worked, Header get! Try decrypt body
            Np = struct.unpack('>I', header[:HEADER_COUNT_NUM_LEN])[0]
            CKp, mk = self._stage_skipped_mk(self.ks['HKr'], self.ks['Nr'], Np, self.ks['CKr'])
            try:
                body = decrypt_symmetric(mk, msg[HEADER_LEN:])
            except (ValueError, KeyError):
                    raise Exception('Undecipherable message')
            
        self.ks['Nr'] = Np + 1
        self.ks['CKr'] = CKp
        return body

    def encrypt_file(self, filename):
        with open(filename, 'r') as f:
            plaintext = f.read()
        ciphertext = base64.b64encode(self.encrypt(plaintext)) + '\n'
        with open(filename+'.asc', 'w') as f:
            lines = [ciphertext[i:i+64] for i in range(0, len(ciphertext), 64)]
            for line in lines:
                f.write(line+'\n')

    def decrypt_file(self, filename):
        with open(filename, 'r') as f:
            ciphertext = base64.b64decode(f.read())
        plaintext = self.decrypt(ciphertext)
        print(plaintext)

    def print_keys(self):
#        print('Your Identity key is:\n' + b2a(self.ks['DHIs']) + '\n')
#        fingerprint = hash_(self.ks['DHIs']).encode('hex').upper()
#        fprint = ''
#        for i in range(0, len(fingerprint), 4):
#            fprint += fingerprint[i:i+2] + ':'
#        print('Your identity key fingerprint is: ')
#        print(fprint[:-1] + '\n')
        print('Your Ratchet key is:\n' + base64.b64encode(self.ks['DHRs']) + '\n')
        if self.handshake_key:
            print('Your Handshake key is:\n' + base64.b64encode(self.handshake_pkey))
        else:
            print('Your Handshake key is not available')

    def print_state(self):
        print('Warning: saving this data to disk is insecure!')
        for key in sorted(self.ks):
             if 'priv' in key:
                 pass
             else:
                 if self.ks[key] is None:
                     print(key + ': None')
                 elif type(self.ks[key]) is bool:
                     if self.ks[key]:
                         print(key + ': True')
                     else:
                         print(key + ': False')
                 elif type(self.ks[key]) is str:
                     try:
                         self.ks[key].decode('ascii')
                         print(key + ': ' + self.ks[key])
                     except UnicodeDecodeError:
                         print(key + ': ' + b2a(self.ks[key]))
                 else:
                     print(key + ': ' + str(self.ks[key]))
        if self.mode is ALICE_MODE:
            print('Mode: Alice')
        else:
            print('Mode: Bob')

class DiskCachePersistence:
    def __init__(self, dbname, dbpassphrase):
        self.dbname = dbname
        self.dbpassphrase = dbpassphrase
        self.db = Cache(dbname)
        # TODO: create encrypted Cache with kdf dbpassphrase
        # TODO: purge expired skippedMessageKey based on store_time

    def save_conversation(self, conversation):
        return self.db.set(b'conv:' + conversation.ks['CONVid'], prefix='conv', tag='conv', retry=True)

    def load_conversation(self, conv_id):
        return self.db.get(b'conv:' + conv_id, None, retry=True)

    def delete_conversation(self, conversation):
        return self.db.pop(b'conv:' + conversation.ks['CONVid'], None, retry=True)

    def get_other_names(self, name):
        names = []
        for k in self.db:
            if k.startswith('conv:'):
                names.append(self.db[k].other_name)
        return names
 
def hash_(data):
    h = SHA256.new(data=data)
    return h.digest()

# HMAC-Based for message/chain keys
def kdf_ck(key, data):
    h = HMAC.new(key, msg=data, digestmod=SHA512)
    return h.digest()

# HKDF-Based (mainly for RK)
def kdf(secret, salt, info=b''):
    return HKDF(secret, 32, salt, SHA512, 1, context=info)

# TODO: replace nacl implementation of ECDH?
def generate_keypair():
    privkey = PrivateKey.generate()
    return Keypair(privkey.encode(), privkey.public_key.encode())


def generate_dh(a, b):
    a = PrivateKey(a)
    b = PublicKey(b)
    return Box(a, b).encode()


def generate_3dh(a, a0, b, b0, mode=ALICE_MODE):
    # Concat 3 DH keys (from 2 keypairs), feed it to KDF
    if mode is ALICE_MODE:
        seed = generate_dh(a, b0) + generate_dh(a0, b) + generate_dh(a0, b0)
    else:
        seed = generate_dh(a0, b) + generate_dh(a, b0) + generate_dh(a0, b0)

    return kdf(seed, b'\x00' * len(seed))


def encrypt_symmetric(key, plaintext):
    nonce = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_SIV, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    assert len(nonce) == 16
    assert len(tag) == 16
    return nonce + tag + ciphertext


def decrypt_symmetric(key, ciphertext):
    cipher = AES.new(key, AES.MODE_SIV, nonce=ciphertext[:16])
    return cipher.decrypt_and_verify(ciphertext[32:], ciphertext[16:32])

