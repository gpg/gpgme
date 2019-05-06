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

c = gpg.Context()

source = gpg.Data(file=support.make_filename("cipher-1.asc"))
sink = gpg.Data()

c.op_decrypt(source, sink)
result = c.op_decrypt_result()
assert not result.unsupported_algorithm, \
    "Unsupported algorithm: {}".format(result.unsupported_algorithm)

support.print_data(sink)

# Idiomatic interface.
with gpg.Context() as c:
    plaintext, _, _ = c.decrypt(open(support.make_filename("cipher-1.asc")), verify=False)
    assert len(plaintext) > 0
    assert plaintext.find(b'Wenn Sie dies lesen k') >= 0, \
        'Plaintext not found'

    plaintext, _, _ = c.decrypt(open(support.make_filename("cipher-3.asc")), verify=False)
    assert len(plaintext) > 0
    assert plaintext.find(b'Reenact Studied Thermos Bonehead Unclasp Opposing') >= 0, \
        'second Plaintext not found'

    plaintext, _, _ = c.decrypt(open(support.make_filename("cipher-no-sig.asc")), verify=False)
    assert len(plaintext) > 0
    assert plaintext.find(b'Viscosity Dispersal Thimble Saturday Flaxseed Deflected') >= 0, \
        'third Plaintext was not found'
