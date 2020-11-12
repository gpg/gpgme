#!/usr/bin/env python

# Copyright (C) 2017 g10 Code GmbH
#
# This file is part of GPGME.
#
# GPGME is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# GPGME is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General
# Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see <https://www.gnu.org/licenses/>.

from __future__ import absolute_import, print_function, unicode_literals

import gpg
import itertools
import time

import support

del absolute_import, print_function, unicode_literals

alpha = "Alpha <alpha@invalid.example.net>"
bravo = "Bravo <bravo@invalid.example.net>"

with support.EphemeralContext() as ctx:
    res = ctx.create_key(alpha, certify=True)
    keys = list(ctx.keylist())
    assert len(keys) == 1, "Weird number of keys created"
    key = keys[0]
    assert key.fpr == res.fpr
    assert len(key.subkeys) == 1, "Expected one primary key and no subkeys"

    def get_subkey(fpr):
        k = ctx.get_key(fpr)
        for sk in k.subkeys:
            if sk.fpr == fpr:
                return sk
        return None

    # Check gpg.constants.create.NOEXPIRE...
    res = ctx.create_subkey(key, expires=False)
    subkey = get_subkey(res.fpr)
    assert subkey.expires == 0, "Expected subkey not to expire"
    assert subkey.can_encrypt, \
        "Default subkey capabilities do not include encryption"

    t = 2 * 24 * 60 * 60
    slack = 5 * 60
    res = ctx.create_subkey(key, expires_in=t)
    subkey = get_subkey(res.fpr)
    assert abs(time.time() + t - subkey.expires) < slack, \
        "subkeys expiration time is off"

    # Check capabilities
    for sign, encrypt, authenticate \
            in itertools.product([False, True],
                                 [False, True],
                                 [False, True]):
        # Filter some out
        if not (sign or encrypt or authenticate):
            # This triggers the default capabilities tested before.
            continue

        res = ctx.create_subkey(
            key, sign=sign, encrypt=encrypt, authenticate=authenticate,
            algorithm="rsa")
        subkey = get_subkey(res.fpr)
        assert sign == subkey.can_sign
        assert encrypt == subkey.can_encrypt
        assert authenticate == subkey.can_authenticate

    # Check algorithm
    res = ctx.create_subkey(key, algorithm="rsa")
    subkey = get_subkey(res.fpr)
    assert subkey.pubkey_algo == 1

    # Check algorithm with size
    res = ctx.create_subkey(key, algorithm="rsa1024")
    subkey = get_subkey(res.fpr)
    assert subkey.pubkey_algo == 1
    assert subkey.length == 1024

    # Check algorithm future-default
    ctx.create_subkey(key, algorithm="future-default")

    # Check passphrase protection.  For this we create a new key
    # so that we have a key with just one encryption subkey.
    bravo_res = ctx.create_key(bravo, certify=True)
    bravo_key = ctx.get_key(bravo_res.fpr)
    assert len(
        bravo_key.subkeys) == 1, "Expected one primary key and no subkeys"

    passphrase = "streng geheim"
    res = ctx.create_subkey(bravo_key, passphrase=passphrase)
    ciphertext, _, _ = ctx.encrypt(
        b"hello there", recipients=[ctx.get_key(bravo_res.fpr)])

    cb_called = False

    def cb(*args):
        global cb_called
        cb_called = True
        return passphrase

    ctx.pinentry_mode = gpg.constants.PINENTRY_MODE_LOOPBACK
    ctx.set_passphrase_cb(cb)

    plaintext, _, _ = ctx.decrypt(ciphertext)
    assert plaintext == b"hello there"
    assert cb_called
