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

import gpg
import support

del absolute_import, print_function, unicode_literals


def fail(msg):
    raise RuntimeError(msg)


def check_result(r, typ):
    if r.invalid_signers:
        fail("Invalid signer found: {}".format(r.invalid_signers.fpr))

    if len(r.signatures) != 2:
        fail("Unexpected number of signatures created")

    for signature in r.signatures:
        if signature.type != typ:
            fail("Wrong type of signature created")

        if signature.pubkey_algo != gpg.constants.pk.DSA:
            fail("Wrong pubkey algorithm reported: {}".format(
                signature.pubkey_algo))

        if signature.hash_algo != gpg.constants.md.SHA1:
            fail("Wrong hash algorithm reported: {}".format(
                signature.hash_algo))

        if signature.sig_class != 1:
            fail("Wrong signature class reported: got {}, want {}".format(
                signature.sig_class, 1))

        if signature.fpr not in ("A0FF4590BB6122EDEF6E3C542D727CC768697734",
                                 "23FD347A419429BACCD5E72D6BC4778054ACD246"):
            fail("Wrong fingerprint reported: {}".format(signature.fpr))


c = gpg.Context()
c.set_textmode(True)
c.set_armor(True)

keys = []
c.op_keylist_start('', True)
keys.append(c.op_keylist_next())
keys.append(c.op_keylist_next())
c.op_keylist_end()

c.signers_add(keys[0])
c.signers_add(keys[1])

for mode in (gpg.constants.sig.mode.NORMAL, gpg.constants.sig.mode.DETACH,
             gpg.constants.sig.mode.CLEAR):
    source = gpg.Data("Hallo Leute\n")
    sink = gpg.Data()

    c.op_sign(source, sink, mode)

    result = c.op_sign_result()
    check_result(result, mode)
    support.print_data(sink)

# Idiomatic interface.
with gpg.Context(armor=True, textmode=True, signers=keys) as c:
    message = "Hallo Leute\n".encode()
    signed, result = c.sign(message)
    check_result(result, gpg.constants.sig.mode.NORMAL)
    assert signed.find(b'BEGIN PGP MESSAGE') > 0, 'Message not found'

    signed, result = c.sign(message, mode=gpg.constants.sig.mode.DETACH)
    check_result(result, gpg.constants.sig.mode.DETACH)
    assert signed.find(b'BEGIN PGP SIGNATURE') > 0, 'Signature not found'

    signed, result = c.sign(message, mode=gpg.constants.sig.mode.CLEAR)
    check_result(result, gpg.constants.sig.mode.CLEAR)
    assert signed.find(b'BEGIN PGP SIGNED MESSAGE') > 0, 'Message not found'
    assert signed.find(message) > 0, 'Message content not found'
    assert signed.find(b'BEGIN PGP SIGNATURE') > 0, 'Signature not found'
