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

import sys
import pyme
from pyme import core, constants
import support

support.init_gpgme(constants.PROTOCOL_OpenPGP)
c = core.Context()
c.set_armor(True)

def check_result(r, typ):
    if r.invalid_signers:
        sys.exit("Invalid signer found: {}".format(r.invalid_signers.fpr))

    if len(r.signatures) != 1:
        sys.exit("Unexpected number of signatures created")

    signature = r.signatures[0]
    if signature.type != typ:
        sys.exit("Wrong type of signature created")

    if signature.pubkey_algo != constants.PK_DSA:
        sys.exit("Wrong pubkey algorithm reported: {}".format(
            signature.pubkey_algo))

    if signature.hash_algo not in (constants.MD_SHA1, constants.MD_RMD160):
        sys.exit("Wrong hash algorithm reported: {}".format(
            signature.hash_algo))

    if signature.sig_class != 0:
        sys.exit("Wrong signature class reported: {}".format(
            signature.sig_class))

    if signature.fpr != "A0FF4590BB6122EDEF6E3C542D727CC768697734":
        sys.exit("Wrong fingerprint reported: {}".format(signature.fpr))

keys = []
keys.append(c.get_key("A0FF4590BB6122EDEF6E3C542D727CC768697734", False))
keys.append(c.get_key("D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2", False))

for recipients in (keys, []):
    source = core.Data("Hallo Leute\n")
    sink = core.Data()

    c.op_encrypt_sign(recipients, constants.ENCRYPT_ALWAYS_TRUST, source, sink)
    result = c.op_encrypt_result()
    assert not result.invalid_recipients, \
        "Invalid recipient encountered: {}".format(
            result.invalid_recipients.fpr)

    result = c.op_sign_result()
    check_result(result, constants.SIG_MODE_NORMAL)

    support.print_data(sink)


# Idiomatic interface.
with pyme.Context(armor=True) as c:
    message = "Hallo Leute\n".encode()
    ciphertext, _, sig_result = c.encrypt(message,
                                          recipients=keys,
                                          always_trust=True)
    assert len(ciphertext) > 0
    assert ciphertext.find(b'BEGIN PGP MESSAGE') > 0, 'Marker not found'
    check_result(sig_result, constants.SIG_MODE_NORMAL)

    c.signers = [c.get_key(support.sign_only, True)]
    c.encrypt(message, recipients=keys, always_trust=True)

    c.signers = [c.get_key(support.encrypt_only, True)]
    try:
        c.encrypt(message, recipients=keys, always_trust=True)
    except pyme.errors.InvalidSigners as e:
        assert len(e.signers) == 1
        assert support.encrypt_only.endswith(e.signers[0].fpr)
    else:
        assert False, "Expected an InvalidSigners error, got none"
