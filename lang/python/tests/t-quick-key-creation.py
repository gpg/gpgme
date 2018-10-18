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
support.assert_gpg_version((2, 1, 2))

del absolute_import, print_function, unicode_literals

alpha = "Alpha <alpha@invalid.example.net>"

with support.EphemeralContext() as ctx:
    res = ctx.create_key(alpha)

    keys = list(ctx.keylist())
    assert len(keys) == 1, "Weird number of keys created"

    key = keys[0]
    assert key.fpr == res.fpr
    assert len(key.subkeys) == 2, "Expected one primary key and one subkey"
    assert key.subkeys[0].expires > 0, "Expected primary key to expire"

    # Try to create a key with the same UID
    try:
        ctx.create_key(alpha)
        assert False, "Expected an error but got none"
    except gpg.errors.GpgError as e:
        pass

    # Try to create a key with the same UID, now with force!
    res2 = ctx.create_key(alpha, force=True)
    assert res.fpr != res2.fpr

# From here on, we use one context, and create unique UIDs
uid_counter = 0


def make_uid():
    global uid_counter
    uid_counter += 1
    return "user{0}@invalid.example.org".format(uid_counter)


with support.EphemeralContext() as ctx:
    # Check gpg.constants.create.NOEXPIRE...
    res = ctx.create_key(make_uid(), expires=False)
    key = ctx.get_key(res.fpr, secret=True)
    assert key.fpr == res.fpr
    assert len(key.subkeys) == 2, "Expected one primary key and one subkey"
    assert key.subkeys[0].expires == 0, "Expected primary key not to expire"

    t = 2 * 24 * 60 * 60
    slack = 5 * 60
    res = ctx.create_key(make_uid(), expires_in=t)
    key = ctx.get_key(res.fpr, secret=True)
    assert key.fpr == res.fpr
    assert len(key.subkeys) == 2, "Expected one primary key and one subkey"
    assert abs(time.time() + t - key.subkeys[0].expires) < slack, \
        "Primary keys expiration time is off"

    # Check capabilities
    for sign, encrypt, certify, authenticate \
            in itertools.product([False, True],
                                 [False, True],
                                 [False, True],
                                 [False, True]):
        # Filter some out
        if not (sign or encrypt or certify or authenticate):
            # This triggers the default capabilities tested before.
            continue
        if (sign or encrypt or authenticate) and not certify:
            # The primary key always certifies.
            continue

        res = ctx.create_key(
            make_uid(),
            algorithm="rsa",
            sign=sign,
            encrypt=encrypt,
            certify=certify,
            authenticate=authenticate)
        key = ctx.get_key(res.fpr, secret=True)
        assert key.fpr == res.fpr
        assert len(key.subkeys) == 1, \
            "Expected no subkey for non-default capabilities"

        p = key.subkeys[0]
        assert sign == p.can_sign
        assert encrypt == p.can_encrypt
        assert certify == p.can_certify
        assert authenticate == p.can_authenticate

    # Check algorithm
    res = ctx.create_key(make_uid(), algorithm="rsa")
    key = ctx.get_key(res.fpr, secret=True)
    assert key.fpr == res.fpr
    for k in key.subkeys:
        assert k.pubkey_algo == 1

    # Check algorithm with size
    res = ctx.create_key(make_uid(), algorithm="rsa1024")
    key = ctx.get_key(res.fpr, secret=True)
    assert key.fpr == res.fpr
    for k in key.subkeys:
        assert k.pubkey_algo == 1
        assert k.length == 1024

    # Check algorithm future-default
    ctx.create_key(make_uid(), algorithm="future-default")

    # Check passphrase protection
    recipient = make_uid()
    passphrase = "streng geheim"
    res = ctx.create_key(recipient, passphrase=passphrase)
    ciphertext, _, _ = ctx.encrypt(
        b"hello there", recipients=[ctx.get_key(res.fpr)])

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
