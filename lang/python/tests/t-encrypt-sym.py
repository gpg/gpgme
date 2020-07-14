#!/usr/bin/env python

# Copyright (C) 2016 g10 Code GmbH
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

import os
import gpg
import support
_ = support  # to appease pyflakes.

del absolute_import, print_function, unicode_literals

for passphrase in ("abc", b"abc"):
    c = gpg.Context()
    c.set_armor(True)
    c.set_pinentry_mode(gpg.constants.PINENTRY_MODE_LOOPBACK)

    source = gpg.Data("Hallo Leute\n")
    cipher = gpg.Data()

    passphrase_cb_called = 0

    def passphrase_cb(hint, desc, prev_bad, hook=None):
        global passphrase_cb_called
        passphrase_cb_called += 1
        return passphrase

    c.set_passphrase_cb(passphrase_cb, None)

    c.op_encrypt([], 0, source, cipher)
    # gpg 2.2.21 has a bug in that for a new passphrase the callback
    # is called twice.  This is fixed in 2.2.22 but a patch was also
    # distributed so that we allow both.
    if support.is_gpg_version((2,2,21)):
        print("Enabling GnuPG 2.2.21 bug 4991 test workaround.")
        assert passphrase_cb_called == 1 or passphrase_cb_called == 2, \
            "Callback called {} times".format(passphrase_cb_called)
    else:
        assert passphrase_cb_called == 1, \
            "Callback called {} times".format(passphrase_cb_called)
    support.print_data(cipher)

    c = gpg.Context()
    c.set_armor(True)
    c.set_pinentry_mode(gpg.constants.PINENTRY_MODE_LOOPBACK)
    c.set_passphrase_cb(passphrase_cb, None)
    plain = gpg.Data()
    cipher.seek(0, os.SEEK_SET)

    c.op_decrypt(cipher, plain)
    # Seems like the passphrase is cached.
    # assert passphrase_cb_called == 2, \
    #    "Callback called {} times".format(passphrase_cb_called)
    support.print_data(plain)

    plain.seek(0, os.SEEK_SET)
    plaintext = plain.read()
    assert plaintext == b"Hallo Leute\n", \
        "Wrong plaintext {!r}".format(plaintext)

# Idiomatic interface.
for passphrase in ("abc", b"abc"):
    with gpg.Context(armor=True) as c:
        # Check that the passphrase callback is not altered.
        def f(*args):
            assert False

        c.set_passphrase_cb(f)

        message = "Hallo Leute\n".encode()
        ciphertext, _, _ = c.encrypt(
            message, passphrase=passphrase, sign=False)
        assert ciphertext.find(b'BEGIN PGP MESSAGE') > 0, 'Marker not found'

        plaintext, _, _ = c.decrypt(ciphertext, passphrase=passphrase)
        assert plaintext == message, 'Message body not recovered'

        assert c._passphrase_cb[1] == f, "Passphrase callback not restored"
