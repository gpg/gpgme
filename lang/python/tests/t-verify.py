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
import os
import pyme
from pyme import core, constants, errors
import support

test_text1 = b"Just GNU it!\n"
test_text1f= b"Just GNU it?\n"
test_sig1 = b"""-----BEGIN PGP SIGNATURE-----

iN0EABECAJ0FAjoS+i9FFIAAAAAAAwA5YmFyw7bDpMO8w58gZGFzIHdhcmVuIFVt
bGF1dGUgdW5kIGpldHp0IGVpbiBwcm96ZW50JS1aZWljaGVuNRSAAAAAAAgAJGZv
b2Jhci4xdGhpcyBpcyBhIG5vdGF0aW9uIGRhdGEgd2l0aCAyIGxpbmVzGhpodHRw
Oi8vd3d3Lmd1Lm9yZy9wb2xpY3kvAAoJEC1yfMdoaXc0JBIAoIiLlUsvpMDOyGEc
dADGKXF/Hcb+AKCJWPphZCphduxSvrzH0hgzHdeQaA==
=nts1
-----END PGP SIGNATURE-----
"""

test_sig2 = b"""-----BEGIN PGP MESSAGE-----

owGbwMvMwCSoW1RzPCOz3IRxjXQSR0lqcYleSUWJTZOvjVdpcYmCu1+oQmaJIleH
GwuDIBMDGysTSIqBi1MApi+nlGGuwDeHao53HBr+FoVGP3xX+kvuu9fCMJvl6IOf
y1kvP4y+8D5a11ang0udywsA
=Crq6
-----END PGP MESSAGE-----
"""

# A message with a prepended but unsigned plaintext packet.
double_plaintext_sig = b"""-----BEGIN PGP MESSAGE-----

rDRiCmZvb2Jhci50eHRF4pxNVGhpcyBpcyBteSBzbmVha3kgcGxhaW50ZXh0IG1l
c3NhZ2UKowGbwMvMwCSoW1RzPCOz3IRxTWISa6JebnG666MFD1wzSzJSixQ81XMV
UlITUxTyixRyKxXKE0uSMxQyEosVikvyCwpSU/S4FNCArq6Ce1F+aXJGvoJvYlGF
erFCTmJxiUJ5flFKMVeHGwuDIBMDGysTyA4GLk4BmO036xgWzMgzt9V85jCtfDFn
UqVooWlGXHwNw/xg/fVzt9VNbtjtJ/fhUqYo0/LyCGEA
=6+AK
-----END PGP MESSAGE-----
"""

def check_result(result, summary, validity, fpr, status, notation):
    assert len(result.signatures) == 1, "Unexpected number of signatures"
    sig = result.signatures[0]
    assert sig.summary == summary, \
        "Unexpected signature summary: {}, want: {}".format(sig.summary,
                                                            summary)
    assert sig.fpr == fpr
    assert errors.GPGMEError(sig.status).getcode() == status

    if notation:
        expected_notations = {
            "bar": (b"\xc3\xb6\xc3\xa4\xc3\xbc\xc3\x9f" +
                    b" das waren Umlaute und jetzt ein prozent%-Zeichen"
                    if sys.version_info[0] < 3 else
                    b"\xc3\xb6\xc3\xa4\xc3\xbc\xc3\x9f".decode() +
                    " das waren Umlaute und jetzt ein prozent%-Zeichen"),
            "foobar.1":  "this is a notation data with 2 lines",
            None: "http://www.gu.org/policy/",
        }
        assert len(sig.notations) == len(expected_notations)

        for r in sig.notations:
            assert not 'name_len' in dir(r)
            assert not 'value_len' in dir(r)
            assert r.name in expected_notations
            assert r.value == expected_notations[r.name], \
                "Expected {!r}, got {!r}".format(expected_notations[r.name],
                                                 r.value)
            expected_notations.pop(r.name)

        assert len(expected_notations) == 0

    assert not sig.wrong_key_usage
    assert sig.validity == validity, \
        "Unexpected signature validity: {}, want: {}".format(
            sig.validity, validity)
    assert errors.GPGMEError(sig.validity_reason).getcode() == errors.NO_ERROR


support.init_gpgme(constants.PROTOCOL_OpenPGP)
c = core.Context()
c.set_armor(True)

# Checking a valid message.
text = core.Data(test_text1)
sig = core.Data(test_sig1)
c.op_verify(sig, text, None)
result = c.op_verify_result()
check_result(result, constants.SIGSUM_VALID | constants.SIGSUM_GREEN,
             constants.VALIDITY_FULL,
             "A0FF4590BB6122EDEF6E3C542D727CC768697734",
             errors.NO_ERROR, True)


# Checking a manipulated message.
text = core.Data(test_text1f)
sig.seek(0, os.SEEK_SET)
c.op_verify(sig, text, None)
result = c.op_verify_result()
check_result(result, constants.SIGSUM_RED, constants.VALIDITY_UNKNOWN,
             "2D727CC768697734", errors.BAD_SIGNATURE, False)

# Checking a normal signature.
text = core.Data()
sig = core.Data(test_sig2)
c.op_verify(sig, None, text)
result = c.op_verify_result()
check_result(result, constants.SIGSUM_VALID | constants.SIGSUM_GREEN,
             constants.VALIDITY_FULL,
             "A0FF4590BB6122EDEF6E3C542D727CC768697734",
             errors.NO_ERROR, False)

# Checking an invalid message.
text = core.Data()
sig = core.Data(double_plaintext_sig)
try:
    c.op_verify(sig, None, text)
except Exception as e:
    assert type(e) == errors.GPGMEError
    assert e.getcode() == errors.BAD_DATA
else:
    assert False, "Expected an error but got none."


# Idiomatic interface.
with pyme.Context(armor=True) as c:
    # Checking a valid message.
    _, result = c.verify(test_text1, test_sig1)
    check_result(result, constants.SIGSUM_VALID | constants.SIGSUM_GREEN,
                 constants.VALIDITY_FULL,
                 "A0FF4590BB6122EDEF6E3C542D727CC768697734",
                 errors.NO_ERROR, True)

    # Checking a manipulated message.
    try:
        c.verify(test_text1f, test_sig1)
    except errors.BadSignatures as e:
        check_result(e.result, constants.SIGSUM_RED,
                     constants.VALIDITY_UNKNOWN,
                     "2D727CC768697734", errors.BAD_SIGNATURE, False)
    else:
        assert False, "Expected an error but got none."

    # Checking a normal signature.
    sig = core.Data(test_sig2)
    data, result = c.verify(test_sig2)
    check_result(result, constants.SIGSUM_VALID | constants.SIGSUM_GREEN,
                 constants.VALIDITY_FULL,
                 "A0FF4590BB6122EDEF6E3C542D727CC768697734",
                 errors.NO_ERROR, False)
    assert data == test_text1

    # Checking an invalid message.
    try:
        c.verify(double_plaintext_sig)
    except errors.GPGMEError as e:
        assert e.getcode() == errors.BAD_DATA
    else:
        assert False, "Expected an error but got none."

    alpha = c.get_key("A0FF4590BB6122EDEF6E3C542D727CC768697734", False)
    bob = c.get_key("D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2", False)

    # Checking a valid message.
    c.verify(test_text1, test_sig1, verify=[alpha])

    try:
        c.verify(test_text1, test_sig1, verify=[alpha, bob])
    except errors.MissingSignatures as e:
        assert len(e.missing) == 1
        assert e.missing[0] == bob
    else:
        assert False, "Expected an error, got none"
