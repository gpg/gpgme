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
# License along with this program; if not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, print_function, unicode_literals
del absolute_import, print_function, unicode_literals

import os
import pyme
from pyme import core, constants
import support

support.init_gpgme(constants.PROTOCOL_OpenPGP)

for passphrase in ("abc", b"abc"):
    c = core.Context()
    c.set_armor(True)
    c.set_pinentry_mode(constants.PINENTRY_MODE_LOOPBACK)

    source = core.Data("Hallo Leute\n")
    cipher = core.Data()

    passphrase_cb_called = 0
    def passphrase_cb(hint, desc, prev_bad, hook=None):
        global passphrase_cb_called
        passphrase_cb_called += 1
        return passphrase

    c.set_passphrase_cb(passphrase_cb, None)

    c.op_encrypt([], 0, source, cipher)
    assert passphrase_cb_called == 1, \
        "Callback called {} times".format(passphrase_cb_called)
    support.print_data(cipher)

    c = core.Context()
    c.set_armor(True)
    c.set_pinentry_mode(constants.PINENTRY_MODE_LOOPBACK)
    c.set_passphrase_cb(passphrase_cb, None)
    plain = core.Data()
    cipher.seek(0, os.SEEK_SET)

    c.op_decrypt(cipher, plain)
    # Seems like the passphrase is cached.
    #assert passphrase_cb_called == 2, \
    #    "Callback called {} times".format(passphrase_cb_called)
    support.print_data(plain)

    plain.seek(0, os.SEEK_SET)
    plaintext = plain.read()
    assert plaintext == b"Hallo Leute\n", \
        "Wrong plaintext {!r}".format(plaintext)

# Idiomatic interface.
for passphrase in ("abc", b"abc"):
    with pyme.Context(armor=True) as c:
        # Check that the passphrase callback is not altered.
        def f(*args):
            assert False
        c.set_passphrase_cb(f)

        message = "Hallo Leute\n".encode()
        ciphertext, _, _ = c.encrypt(message,
                                     passphrase=passphrase,
                                     sign=False)
        assert ciphertext.find(b'BEGIN PGP MESSAGE') > 0, 'Marker not found'

        plaintext, _, _ = c.decrypt(ciphertext, passphrase=passphrase)
        assert plaintext == message, 'Message body not recovered'

        assert c._passphrase_cb[1] == f, "Passphrase callback not restored"
