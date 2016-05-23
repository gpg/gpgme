#!/usr/bin/env python3

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

import sys
from pyme import core, constants
import support

def check_result(r, typ):
    if r.invalid_signers:
        sys.exit("Invalid signer found: {}".format(r.invalid_signers.fpr))

    if len(r.signatures) != 2:
        sys.exit("Unexpected number of signatures created")

    for signature in r.signatures:
        if signature.type != typ:
            sys.exit("Wrong type of signature created")

        if signature.pubkey_algo != constants.PK_DSA:
            sys.exit("Wrong pubkey algorithm reported: {}".format(
                signature.pubkey_algo))

        if signature.hash_algo != constants.MD_SHA1:
            sys.exit("Wrong hash algorithm reported: {}".format(
                signature.hash_algo))

        if signature.sig_class != 1:
            sys.exit("Wrong signature class reported: {}".format(
                signature.sig_class))

        if signature.fpr not in ("A0FF4590BB6122EDEF6E3C542D727CC768697734",
                                 "23FD347A419429BACCD5E72D6BC4778054ACD246"):
            sys.exit("Wrong fingerprint reported: {}".format(signature.fpr))


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
