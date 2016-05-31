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

import os
from pyme import core, constants, errors
import support

test_text1 = "Just GNU it!\n"
test_text1f= "Just GNU it?\n"
test_sig1 = """-----BEGIN PGP SIGNATURE-----

iN0EABECAJ0FAjoS+i9FFIAAAAAAAwA5YmFyw7bDpMO8w58gZGFzIHdhcmVuIFVt
bGF1dGUgdW5kIGpldHp0IGVpbiBwcm96ZW50JS1aZWljaGVuNRSAAAAAAAgAJGZv
b2Jhci4xdGhpcyBpcyBhIG5vdGF0aW9uIGRhdGEgd2l0aCAyIGxpbmVzGhpodHRw
Oi8vd3d3Lmd1Lm9yZy9wb2xpY3kvAAoJEC1yfMdoaXc0JBIAoIiLlUsvpMDOyGEc
dADGKXF/Hcb+AKCJWPphZCphduxSvrzH0hgzHdeQaA==
=nts1
-----END PGP SIGNATURE-----
"""

test_sig2 = """-----BEGIN PGP MESSAGE-----

owGbwMvMwCSoW1RzPCOz3IRxjXQSR0lqcYleSUWJTZOvjVdpcYmCu1+oQmaJIleH
GwuDIBMDGysTSIqBi1MApi+nlGGuwDeHao53HBr+FoVGP3xX+kvuu9fCMJvl6IOf
y1kvP4y+8D5a11ang0udywsA
=Crq6
-----END PGP MESSAGE-----
"""

# A message with a prepended but unsigned plaintext packet.
double_plaintext_sig = """-----BEGIN PGP MESSAGE-----

rDRiCmZvb2Jhci50eHRF4pxNVGhpcyBpcyBteSBzbmVha3kgcGxhaW50ZXh0IG1l
c3NhZ2UKowGbwMvMwCSoW1RzPCOz3IRxTWISa6JebnG666MFD1wzSzJSixQ81XMV
UlITUxTyixRyKxXKE0uSMxQyEosVikvyCwpSU/S4FNCArq6Ce1F+aXJGvoJvYlGF
erFCTmJxiUJ5flFKMVeHGwuDIBMDGysTyA4GLk4BmO036xgWzMgzt9V85jCtfDFn
UqVooWlGXHwNw/xg/fVzt9VNbtjtJ/fhUqYo0/LyCGEA
=6+AK
-----END PGP MESSAGE-----
"""

def check_result(result, summary, fpr, status, notation):
    assert len(result.signatures) == 1, "Unexpected number of signatures"
    sig = result.signatures[0]
    assert sig.summary == summary, "Unexpected signature summary"
    assert sig.fpr == fpr
    assert errors.GPGMEError(sig.status).getcode() == status

    if notation:
        expected_notations = {
            "bar": b"\xc3\xb6\xc3\xa4\xc3\xbc\xc3\x9f".decode() +
            " das waren Umlaute und jetzt ein prozent%-Zeichen",
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
    assert sig.validity == constants.VALIDITY_UNKNOWN
    assert errors.GPGMEError(sig.validity_reason).getcode() == errors.NO_ERROR


support.init_gpgme(constants.PROTOCOL_OpenPGP)
c = core.Context()
c.set_armor(True)

# Checking a valid message.
text = core.Data(test_text1)
sig = core.Data(test_sig1)
c.op_verify(sig, text, None)
result = c.op_verify_result()
check_result(result, 0, "A0FF4590BB6122EDEF6E3C542D727CC768697734",
             errors.NO_ERROR, True)


# Checking a manipulated message.
text = core.Data(test_text1f)
sig.seek(0, os.SEEK_SET)
c.op_verify(sig, text, None)
result = c.op_verify_result()
check_result(result, constants.SIGSUM_RED, "2D727CC768697734",
             errors.BAD_SIGNATURE, False)

# Checking a normal signature.
text = core.Data()
sig = core.Data(test_sig2)
c.op_verify(sig, None, text)
result = c.op_verify_result()
check_result(result, 0, "A0FF4590BB6122EDEF6E3C542D727CC768697734",
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
