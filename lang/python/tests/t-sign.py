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

del absolute_import, print_function, unicode_literals


def fail(msg):
    raise RuntimeError(msg)


def check_result(r, typ):
    if r.invalid_signers:
        fail("Invalid signer found: {}".format(r.invalid_signers.fpr))

    if len(r.signatures) != 1:
        fail("Unexpected number of signatures created")

    signature = r.signatures[0]
    if signature.type != typ:
        fail("Wrong type of signature created")

    if signature.pubkey_algo != gpg.constants.pk.DSA:
        fail("Wrong pubkey algorithm reported: {}".format(
            signature.pubkey_algo))

    if signature.hash_algo != gpg.constants.md.SHA1:
        fail("Wrong hash algorithm reported: {}".format(signature.hash_algo))

    if signature.sig_class != 1:
        fail("Wrong signature class reported: {}".format(signature.sig_class))

    if signature.fpr != "A0FF4590BB6122EDEF6E3C542D727CC768697734":
        fail("Wrong fingerprint reported: {}".format(signature.fpr))


c = gpg.Context()
c.set_textmode(True)
c.set_armor(True)

source = gpg.Data("Hallo Leute\n")
sink = gpg.Data()

c.op_sign(source, sink, gpg.constants.sig.mode.NORMAL)

result = c.op_sign_result()
check_result(result, gpg.constants.sig.mode.NORMAL)
support.print_data(sink)

# Now a detached signature.
source.seek(0, os.SEEK_SET)
sink = gpg.Data()

c.op_sign(source, sink, gpg.constants.sig.mode.DETACH)

result = c.op_sign_result()
check_result(result, gpg.constants.sig.mode.DETACH)
support.print_data(sink)

# And finally a cleartext signature.  */
source.seek(0, os.SEEK_SET)
sink = gpg.Data()

c.op_sign(source, sink, gpg.constants.sig.mode.CLEAR)

result = c.op_sign_result()
check_result(result, gpg.constants.sig.mode.CLEAR)
support.print_data(sink)

# Idiomatic interface.
with gpg.Context(armor=True, textmode=True) as c:
    message = "Hallo Leute\n".encode()
    signed, _ = c.sign(message)
    assert len(signed) > 0
    assert signed.find(b'BEGIN PGP MESSAGE') > 0, 'Message not found'

    signed, _ = c.sign(message, mode=gpg.constants.sig.mode.DETACH)
    assert len(signed) > 0
    assert signed.find(b'BEGIN PGP SIGNATURE') > 0, 'Signature not found'

    signed, _ = c.sign(message, mode=gpg.constants.sig.mode.CLEAR)
    assert len(signed) > 0
    assert signed.find(b'BEGIN PGP SIGNED MESSAGE') > 0, 'Message not found'
    assert signed.find(message) > 0, 'Message content not found'
    assert signed.find(b'BEGIN PGP SIGNATURE') > 0, 'Signature not found'

with gpg.Context() as c:
    message = "Hallo Leute\n".encode()

    c.signers = [c.get_key(support.sign_only, True)]
    c.sign(message)

    c.signers = [c.get_key(support.encrypt_only, True)]
    try:
        c.sign(message)
    except gpg.errors.InvalidSigners as e:
        assert len(e.signers) == 1
        assert support.encrypt_only.endswith(e.signers[0].fpr)
    else:
        assert False, "Expected an InvalidSigners error, got none"
