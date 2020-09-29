import errno
import os
import sys
import struct
from functools import wraps
from getpass import getpass
from threading import Lock
from time import time
import base64

import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512, SHA256
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


def sync(f):
    @wraps(f)
    def synced_f(self, *args, **kwargs):
        with self.lock:
            return f(self, *args, **kwargs)
    return synced_f


class Axolotl(object):
    def __init__(self, name, dbname='axolotl', dbpassphrase=''):
        self.name = name
        self.dbname = dbname
        if dbpassphrase is None:
            self.dbpassphrase = None
        elif dbpassphrase != '':
            self.dbpassphrase = hash_(dbpassphrase.encode())
        else:
            self.dbpassphrase = getpass('Database passphrase for '+ self.name + ': ').strip()
        self.conversation = AxolotlConversation(self, keys=dict(), mode=None)
        self.state['DHIs_priv'], self.state['DHIs'] = generate_keypair()
        self.state['DHRs_priv'], self.state['DHRs'] = generate_keypair()
        self.handshakeKey, self.handshakePKey = generate_keypair()
        self.storeTime = 2*86400 # minimum time (seconds) to store missed ephemeral message keys
        self.persistence = DiskCachePersistence(self.dbname,
                                             self.dbpassphrase,
                                             self.storeTime)

    @property
    def state(self):
        return self.conversation.keys

    @state.setter
    def state(self, state):
        self.conversation.keys = state

    @property
    def mode(self):
        return self.conversation.mode

    @mode.setter
    def mode(self, mode):
        self.conversation.mode = mode

    @property
    def db(self):
        return self.persistence.db

    @db.setter
    def db(self, db):
        self.persistence.db = db

    def tripleDH(self, a, a0, B, B0):
        if self.mode == None:
            raise Exception("Can't create stat without mode")
        return generate_3dh(a, a0, B, B0, self.mode)

    def genDH(self, a, B):
        return generate_dh(a, B)

    def genKey(self):
        return generate_keypair()

    def initState(self, other_name, other_identityKey, other_handshakeKey,
                  other_ratchetKey, verify=True):
        if verify:
            print('Confirm ' + other_name + ' has identity key fingerprint:\n')
            fingerprint = hash_(other_identityKey.encode()).encode('hex').upper()
            fprint = ''
            for i in range(0, len(fingerprint), 4):
                fprint += fingerprint[i:i+2] + ':'
            print(fprint[:-1] + '\n')
            print('Be sure to verify this fingerprint with ' + other_name + ' by some out-of-band method!')
            print('Otherwise, you may be subject to a Man-in-the-middle attack!\n')
            ans = raw_input('Confirm? y/N: ').strip()
            if ans != 'y':
                print('Key fingerprint not confirmed - exiting...')
                sys.exit()

        self.conversation = self.init_conversation(other_name,
                                                   self.state['DHIs_priv'],
                                                   self.state['DHIs'],
                                                   self.handshakeKey,
                                                   other_identityKey,
                                                   other_handshakeKey,
                                                   self.state['DHRs_priv'],
                                                   self.state['DHRs'],
                                                   other_ratchetKey)

    def init_conversation(self, other_name,
                          priv_identity_key, identity_key, priv_handshake_key,
                          other_identity_key, other_handshake_key,
                          priv_ratchet_key=None, ratchet_key=None,
                          other_ratchet_key=None, mode=None):
        if mode is None:
            if identity_key < other_identity_key:
                mode = ALICE_MODE
            else:
                mode = BOB_MODE

        mkey = generate_3dh(priv_identity_key, priv_handshake_key,
                            other_identity_key, other_handshake_key,
                            mode)

        return self.create_conversation(other_name,
                                        mkey,
                                        mode,
                                        priv_identity_key,
                                        identity_key,
                                        other_identity_key,
                                        priv_ratchet_key,
                                        ratchet_key,
                                        other_ratchet_key)

    def createState(self, other_name, mkey, mode=None, other_identityKey=None, other_ratchetKey=None):
        if mode is not None:
            self.mode = mode
        else:
            if self.mode is None: # mode not selected
                raise Exception("Can't create stat without mode")

        self.conversation = self.create_conversation(other_name,
                                                     mkey,
                                                     self.mode,
                                                     self.state['DHIs_priv'],
                                                     self.state['DHIs'],
                                                     other_identityKey,
                                                     self.state['DHRs_priv'],
                                                     self.state['DHRs'],
                                                     other_ratchetKey)

        self.ratchetKey = False
        self.ratchetPKey = False

    def create_conversation(self, other_name, mkey, mode,
                            priv_identity_key, identity_key,
                            other_identity_key,
                            priv_ratchet_key=None, ratchet_key=None,
                            other_ratchet_key=None):
        if mode is ALICE_MODE:
            HKs = None
            HKr = kdf(mkey, SALTS['HK'][BOB_MODE])
            CKs = None
            CKr = kdf(mkey, SALTS['CK'][BOB_MODE])
            DHRs_priv = None
            DHRs = None
            DHRr = other_ratchet_key
            Ns = 0
            Nr = 0
            PNs = 0
            ratchet_flag = True
        else: # bob mode
            HKs = kdf(mkey, SALTS['HK'][BOB_MODE])
            HKr = None
            CKs = kdf(mkey, SALTS['CK'][BOB_MODE])
            CKr = None
            DHRs_priv = priv_ratchet_key
            DHRs = ratchet_key
            DHRr = None
            Ns = 0
            Nr = 0
            PNs = 0
            ratchet_flag = False
        RK = kdf(mkey, SALTS['RK'])
        NHKs = kdf(mkey, SALTS['NHK'][mode])
        NHKr = kdf(mkey, SALTS['NHK'][not mode])
        CONVid = kdf(mkey, SALTS['CONVid'])
        DHIr = other_identity_key

        keys = \
               { 'name': self.name,
                 'other_name': other_name,
                 'RK': RK,
                 'HKs': HKs,
                 'HKr': HKr,
                 'NHKs': NHKs,
                 'NHKr': NHKr,
                 'CKs': CKs,
                 'CKr': CKr,
                 'DHIs_priv': priv_identity_key,
                 'DHIs': identity_key,
                 'DHIr': DHIr,
                 'DHRs_priv': DHRs_priv,
                 'DHRs': DHRs,
                 'DHRr': DHRr,
                 'CONVid': CONVid,
                 'Ns': Ns,
                 'Nr': Nr,
                 'PNs': PNs,
                 'ratchet_flag': ratchet_flag,
               }

        return AxolotlConversation(self, keys, mode)

    def encrypt(self, plaintext):
        return self.conversation.encrypt(plaintext)

    def decrypt(self, msg):
        return self.conversation.decrypt(msg)

    def encrypt_file(self, filename):
        self.conversation.encrypt_file(filename)

    def decrypt_file(self, filename):
        self.conversation.decrypt_file(filename)

    def printKeys(self):
        self.conversation.print_keys()

    def saveState(self):
        self.save_conversation(self.conversation)

    def save_conversation(self, conversation):
        self.persistence.save_conversation(conversation)

    def loadState(self, name, other_name):
        self.conversation = self.load_conversation(other_name, name)
        if self.conversation:
            return
        else:
            return False

    def load_conversation(self, other_name, name=None):
        return self.persistence.load_conversation(self,
                                                  name or self.name,
                                                  other_name)

    def delete_conversation(self, conversation):
        return self.persistence.delete_conversation(conversation)

    def get_other_names(self):
        return self.persistence.get_other_names(self.name)

    def printState(self):
        self.conversation.print_state()


class AxolotlConversation:
    def __init__(self, axolotl, keys, mode, staged_hk_mk=None):
        self._axolotl = axolotl
        self.lock = Lock()
        self.keys = keys
        self.mode = mode
        self.staged_hk_mk = staged_hk_mk or dict()
        self.staged = False

        self.handshake_key = None
        self.handshake_pkey = None

    @property
    def name(self):
        return self.keys['name']

    @name.setter
    def name(self, name):
        self.keys['name'] = name

    @property
    def other_name(self):
        return self.keys['other_name']

    @other_name.setter
    def other_name(self, other_name):
        self.keys['other_name'] = other_name

    @property
    def id_(self):
        return self.keys['CONVid']

    @id_.setter
    def id_(self, id_):
        self.keys['CONVid'] = id_

    @property
    def ns(self):
        return self.keys['Ns']

    @ns.setter
    def ns(self, ns):
        self.keys['Ns'] = ns

    @property
    def nr(self):
        return self.keys['Nr']

    @nr.setter
    def nr(self, nr):
        self.keys['Nr'] = nr

    @property
    def pns(self):
        return self.keys['PNs']

    @pns.setter
    def pns(self, pns):
        self.keys['PNs'] = pns

    @property
    def ratchet_flag(self):
        return self.keys['ratchet_flag']

    @ratchet_flag.setter
    def ratchet_flag(self, ratchet_flag):
        self.keys['ratchet_flag'] = ratchet_flag

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
            mk = hash_(ckp + b'0')
            ckp = hash_(ckp + b'1')
            self.staged_hk_mk[mk] = SkippedMessageKey(mk, hkr, timestamp)
            self.staged = True
        mk = hash_(ckp + b'0')
        ckp = hash_(ckp + b'1')
        return ckp, mk

    @sync
    def encrypt(self, plaintext):
        if self.ratchet_flag:
            self.keys['DHRs_priv'], self.keys['DHRs'] = generate_keypair()
            self.keys['HKs'] = self.keys['NHKs']
            self.keys['RK'] = hash_(self.keys['RK'] +
                                    generate_dh(self.keys['DHRs_priv'], self.keys['DHRr']))
            self.keys['NHKs'] = kdf(self.keys['RK'], SALTS['NHK'][self.mode])
            self.keys['CKs'] = kdf(self.keys['RK'], SALTS['CK'][self.mode])
            self.pns = self.ns
            self.ns = 0
            self.ratchet_flag = False
        mk = hash_(self.keys['CKs'] + b'0')
        msg1 = encrypt_symmetric(
            self.keys['HKs'],
            struct.pack('>I', self.ns) + struct.pack('>I', self.pns) +
            self.keys['DHRs'])
        msg2 = encrypt_symmetric(mk, plaintext.encode())
        pad_length = HEADER_LEN - len(msg1)
        pad = os.urandom(pad_length - HEADER_PAD_NUM_LEN) + chr(pad_length).encode()
        msg = msg1 + pad + msg2
        self.ns += 1
        self.keys['CKs'] = hash_(self.keys['CKs'] + b'1')
        return msg

    @sync
    def decrypt(self, msg):
        pad = msg[HEADER_LEN-HEADER_PAD_NUM_LEN:HEADER_LEN]
        pad_length = ord(pad)
        msg1 = msg[:HEADER_LEN-pad_length]

        body = self._try_skipped_mk(msg, pad_length)
        if body and body != '':
            return body

        header = None
        if self.keys['HKr']:
            try:
                header = decrypt_symmetric(self.keys['HKr'], msg1)
            except (ValueError, KeyError):
                pass
        if header and header != '':
            Np = struct.unpack('>I', header[:HEADER_COUNT_NUM_LEN])[0]
            CKp, mk = self._stage_skipped_mk(self.keys['HKr'], self.nr, Np, self.keys['CKr'])
            try:
                body = decrypt_symmetric(mk, msg[HEADER_LEN:])
            except (ValueError, KeyError):
                raise Exception('Undecipherable message')
        else:
            try:
                header = decrypt_symmetric(self.keys['NHKr'], msg1)
            except (ValueError, KeyError):
                pass
            if self.ratchet_flag or not header or header == '':
                raise Exception('Undecipherable message')
            Np = struct.unpack('>I', header[:HEADER_COUNT_NUM_LEN])[0]
            PNp = struct.unpack('>I', header[HEADER_COUNT_NUM_LEN:HEADER_COUNT_NUM_LEN*2])[0]
            DHRp = header[HEADER_COUNT_NUM_LEN*2:]
            if self.keys['CKr']:
                self._stage_skipped_mk(self.keys['HKr'], self.nr, PNp, self.keys['CKr'])
            HKp = self.keys['NHKr']
            RKp = hash_(self.keys['RK'] + generate_dh(self.keys['DHRs_priv'], DHRp))
            NHKp = kdf(RKp, SALTS['NHK'][not self.mode])
            CKp = kdf(RKp, SALTS['CK'][not self.mode])
            CKp, mk = self._stage_skipped_mk(HKp, 0, Np, CKp)
            try:
                body = decrypt_symmetric(mk, msg[HEADER_LEN:])
            except (ValueError, KeyError):
                pass
            if not body or body == '':
                raise Exception('Undecipherable message')
            self.keys['RK'] = RKp
            self.keys['HKr'] = HKp
            self.keys['NHKr'] = NHKp
            self.keys['DHRr'] = DHRp
            self.keys['DHRs_priv'] = None
            self.keys['DHRs'] = None
            self.ratchet_flag = True
        self.nr = Np + 1
        self.keys['CKr'] = CKp
        return body

    def encrypt_file(self, filename):
        with open(filename, 'r') as f:
            plaintext = f.read()
        ciphertext = b2a(self.encrypt(plaintext)) + '\n'
        with open(filename+'.asc', 'w') as f:
            lines = [ciphertext[i:i+64] for i in xrange(0, len(ciphertext), 64)]
            for line in lines:
                f.write(line+'\n')

    def decrypt_file(self, filename):
        with open(filename, 'r') as f:
            ciphertext = a2b(f.read())
        plaintext = self.decrypt(ciphertext)
        print(plaintext)


    def save(self):
        self._axolotl.save_conversation(self)

    def delete(self):
        self._axolotl.delete_conversation(self)

    def print_keys(self):
        print('Your Identity key is:\n' + b2a(self.keys['DHIs']) + '\n')
        fingerprint = hash_(self.keys['DHIs']).encode('hex').upper()
        fprint = ''
        for i in range(0, len(fingerprint), 4):
            fprint += fingerprint[i:i+2] + ':'
        print('Your identity key fingerprint is: ')
        print(fprint[:-1] + '\n')
        print('Your Ratchet key is:\n' + b2a(self.keys['DHRs']) + '\n')
        if self.handshake_key:
            print('Your Handshake key is:\n' + b2a(self.handshake_pkey))
        else:
            print('Your Handshake key is not available')

    def print_state(self):
        print('Warning: saving this data to disk is insecure!')
        for key in sorted(self.keys):
             if 'priv' in key:
                 pass
             else:
                 if self.keys[key] is None:
                     print(key + ': None')
                 elif type(self.keys[key]) is bool:
                     if self.keys[key]:
                         print(key + ': True')
                     else:
                         print(key + ': False')
                 elif type(self.keys[key]) is str:
                     try:
                         self.keys[key].decode('ascii')
                         print(key + ': ' + self.keys[key])
                     except UnicodeDecodeError:
                         print(key + ': ' + b2a(self.keys[key]))
                 else:
                     print(key + ': ' + str(self.keys[key]))
        if self.mode is ALICE_MODE:
            print('Mode: Alice')
        else:
            print('Mode: Bob')


class SkippedMessageKey:
    def __init__(self, mk, hk, timestamp):
        self.mk = mk
        self.hk = hk
        self.timestamp = timestamp


class DiskCachePersistence:
    def __init__(self, dbname, dbpassphrase, store_time):
        self.dbname = dbname
        self.dbpassphrase = dbpassphrase
        self.store_time = store_time
        self.db = Cache(dbname)
        # TODO: create encrypted Cache with kdf dbpassphrase
        # TODO: purge expired skippedMessageKey based on store_time

    def save_conversation(self, conversation):
        return self.db.set(f'conv:{conversation.name}-{conversation.other_name}', prefix='conv', tag='conv', retry=True)

    def load_conversation(self, axolotl, name, other_name):
        return self.db.get(f'conv:{conversation.name}-{conversation.other_name}', None)

    def delete_conversation(self, name, other_name):
        return self.db.pop(f'conv:{conversation.name}-{conversation.other_name}', None)

    def get_other_names(self, name):
        names = []
        for k in self.db:
            if k.startswith('conv:'):
                names.append(self.db[k].other_name)
        return names

Keypair = namedtuple('Keypair', 'priv pub')
     
def a2b(a):
    return base64.b64decode(b)

def b2a(b):
    return base64.b64encode(b)


def hash_(data):
    h = SHA256.new()
    h.update(data)
    return h.digest()


def kdf(secret, salt):
    return HKDF(secret, 32, salt, SHA512, 1)

# TODO: replace nacl implementation of ECDH?
def generate_keypair():
    privkey = PrivateKey.generate()
    return Keypair(privkey.encode(), privkey.public_key.encode())


def generate_dh(a, b):
    a = PrivateKey(a)
    b = PublicKey(b)
    return Box(a, b).encode()


def generate_3dh(a, a0, b, b0, mode=ALICE_MODE):
    if mode is ALICE_MODE:
        return hash_(generate_dh(a, b0) +
                     generate_dh(a0, b) +
                     generate_dh(a0, b0))
    else:
        return hash_(generate_dh(a0, b) +
                     generate_dh(a, b0) +
                     generate_dh(a0, b0))


def encrypt_symmetric(key, plaintext):
    nonce = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_SIV, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(bytes(plaintext))
    assert len(nonce) == 16
    assert len(tag) == 16
    return nonce + tag + ciphertext


def decrypt_symmetric(key, ciphertext):
    cipher = AES.new(key, AES.MODE_SIV, nonce=ciphertext[:16])
    return cipher.decrypt_and_verify(ciphertext[32:], ciphertext[16:32])

