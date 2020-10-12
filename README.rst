Python implementation of the Double Ratchet Algorithm.
======================================================
This is a fork of `<https://github.com/rxcomm/pyaxo>`_ aiming to update it to a more maintainable state.

Check out the `py3` branch for the old `pyaxo` with python3 fixes.

Notable Changes
---------------
* Change symmetric encryption to AES128-SIV (from XSalsa20/Poly)
* Change KDF from pkdf2 to hkdf (sha512)

  * Added `info` recommendation for KDF_RK
  * Used RK as salt, DH as input *instead* of concat (§5.2.KDF_RK)
  
* Change Chain/Message KDF to HMAC512 as recommended
* Updated `3dh` to X3DH specs

  * Added a simpler interface to create ratchet from X3DH

* Change datastore from sqlite3 to diskcache
* Make everything Python3 compatible
* A large amount of code trimming/refactoring/documentation


Overview
--------
The Double Ratchet Algorithm is a protocol (similar to OTR) that
provides for perfect forward secrecy in (a)synchronous
communications. It uses triple Diffie-Hellman for
authentication and ECDHE for perfect forward secrecy.
The protocol is lighter and more robust than the OTR
protocol - providing better forward and future secrecy,
as well as deniability.

The protocol was developed by Trevor Perrin and Moxie
Marlinspike. Its chief use currently is in the Open Whisper Systems
Signal package.

A nice writeup of the protocol is on the `Open Whisper Systems Blog`_.
You can find the most recent specification of the protocol
`here <https://whispersystems.org/docs/specifications/doubleratchet/>`_.

Basic Example
-------------

.. code-block:: python

  from pyaxo_ng import AxolotlConversation

  mkey = get_random_bytes(32) # Pre-shared (hashlib.sha256(key).digest() also possible)
  # ---Init A---
  a = AxolotlConversation.new_from_mkey(mkey)
  # ---Init B---
  b = AxolotlConversation.new_from_mkey(mkey, a.ks['DHRs'])

  # ---Encrypt---
  data = b'Test msg'
  c = a.encrypt(data)
  assert b.decrypt(c) == data


X3DH in pyaxo-ng
----------------
Pyaxo-ng also provides an interface for X3DH unlike pyaxo.
This can be used when first creating an 'anonymous' connection with a new remote user, like what is common in most instant messagers
This can be used as in the following example:

.. code-block:: python

  rKeys, rResolve = AxolotlConversation.new_from_x3dh(mode=False) # Bob/Initiator
  oKeys, oResolve = AxolotlConversation.new_from_x3dh(mode=True) # Alice/Recipient

  rConv = rResolve(*oKeys)
  oConv = oResolve(*rKeys)

  o = b'Data'
  c1 = rConv.encrypt(o)
  assert oConv.decrypt(c1) == o


Installation instructions
-------------------------
Make sure that you have the following::

    # If using Debian/Ubuntu
    sudo apt-get install gcc libffi-dev libsodium-dev python-dev

    # If using Fedora
    sudo yum install gcc libffi-devel libsodium-devel python-devel redhat-rpm-config

If you use *setuptools*, change to pyaxo's source folder and install
with::

    sudo python setup.py install

**pyaxo will be ready for use!**

Usage
-----
There are several examples showing usage. There are also
``encrypt_pipe()`` and ``decrypt_pipe()`` methods for use in
certain applications. I haven't put together an example using
them yet, but it should be straightforward.

Bugs, etc. should be reported to the *pyaxo* github `issues page`_.

.. _`issues page`: https://github.com/i404788/pyaxo-ng/issues
.. _`pip`: https://pypi.python.org/pypi/pip
.. _`setuptools`: https://pypi.python.org/pypi/setuptools
.. _`Open Whisper Systems Blog`: https://whispersystems.org/blog/advanced-ratcheting/
