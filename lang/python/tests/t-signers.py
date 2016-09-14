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

import pyme
from pyme import core, constants
import support

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

        if signature.pubkey_algo != constants.PK_DSA:
            fail("Wrong pubkey algorithm reported: {}".format(
                signature.pubkey_algo))

        if signature.hash_algo != constants.MD_SHA1:
            fail("Wrong hash algorithm reported: {}".format(
                signature.hash_algo))

        if signature.sig_class != 1:
            fail("Wrong signature class reported: got {}, want {}".format(
                signature.sig_class, 1))

        if signature.fpr not in ("A0FF4590BB6122EDEF6E3C542D727CC768697734",
                                 "23FD347A419429BACCD5E72D6BC4778054ACD246"):
            fail("Wrong fingerprint reported: {}".format(signature.fpr))


support.init_gpgme(constants.PROTOCOL_OpenPGP)
c = core.Context()
c.set_textmode(True)
c.set_armor(True)

keys = []
c.op_keylist_start('', True)
keys.append(c.op_keylist_next())
keys.append(c.op_keylist_next())
c.op_keylist_end()

c.signers_add(keys[0])
c.signers_add(keys[1])

for mode in (constants.SIG_MODE_NORMAL, constants.SIG_MODE_DETACH,
             constants.SIG_MODE_CLEAR):
    source = core.Data("Hallo Leute\n")
    sink = core.Data()

    c.op_sign(source, sink, mode)

    result = c.op_sign_result()
    check_result(result, mode)
    support.print_data(sink)

# Idiomatic interface.
with pyme.Context(armor=True, textmode=True, signers=keys) as c:
    message = "Hallo Leute\n".encode()
    signed, result = c.sign(message)
    check_result(result, constants.SIG_MODE_NORMAL)
    assert signed.find(b'BEGIN PGP MESSAGE') > 0, 'Message not found'

    signed, result = c.sign(message, mode=constants.SIG_MODE_DETACH)
    check_result(result, constants.SIG_MODE_DETACH)
    assert signed.find(b'BEGIN PGP SIGNATURE') > 0, 'Signature not found'

    signed, result = c.sign(message, mode=constants.SIG_MODE_CLEAR)
    check_result(result, constants.SIG_MODE_CLEAR)
    assert signed.find(b'BEGIN PGP SIGNED MESSAGE') > 0, 'Message not found'
    assert signed.find(message) > 0, 'Message content not found'
    assert signed.find(b'BEGIN PGP SIGNATURE') > 0, 'Signature not found'
