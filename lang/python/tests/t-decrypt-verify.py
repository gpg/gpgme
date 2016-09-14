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
from pyme import core, constants, errors
import support

def check_verify_result(result, summary, fpr, status):
    assert len(result.signatures) == 1, "Unexpected number of signatures"
    sig = result.signatures[0]
    assert sig.summary == summary, "Unexpected signature summary"
    assert sig.fpr == fpr
    assert errors.GPGMEError(sig.status).getcode() == status
    assert len(sig.notations) == 0
    assert not sig.wrong_key_usage
    assert sig.validity == constants.VALIDITY_FULL
    assert errors.GPGMEError(sig.validity_reason).getcode() == errors.NO_ERROR

support.init_gpgme(constants.PROTOCOL_OpenPGP)
c = core.Context()

source = core.Data(file=support.make_filename("cipher-2.asc"))
sink = core.Data()

c.op_decrypt_verify(source, sink)
result = c.op_decrypt_result()
assert not result.unsupported_algorithm, \
    "Unsupported algorithm: {}".format(result.unsupported_algorithm)

support.print_data(sink)

verify_result = c.op_verify_result()
check_verify_result(verify_result,
                    constants.SIGSUM_VALID | constants.SIGSUM_GREEN,
                    "A0FF4590BB6122EDEF6E3C542D727CC768697734",
                    errors.NO_ERROR)

# Idiomatic interface.
with pyme.Context() as c:
    alpha = c.get_key("A0FF4590BB6122EDEF6E3C542D727CC768697734", False)
    bob = c.get_key("D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2", False)
    plaintext, _, verify_result = \
        c.decrypt(open(support.make_filename("cipher-2.asc")), verify=[alpha])
    assert plaintext.find(b'Wenn Sie dies lesen k') >= 0, \
        'Plaintext not found'
    check_verify_result(verify_result,
                        constants.SIGSUM_VALID | constants.SIGSUM_GREEN,
                        "A0FF4590BB6122EDEF6E3C542D727CC768697734",
                        errors.NO_ERROR)

    try:
        c.decrypt(open(support.make_filename("cipher-2.asc")),
                  verify=[alpha, bob])
    except errors.MissingSignatures as e:
        assert len(e.missing) == 1
        assert e.missing[0] == bob
    else:
        assert False, "Expected an error, got none"
