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

support.init_gpgme(constants.PROTOCOL_OpenPGP)
c = core.Context()

source = core.Data(file=support.make_filename("cipher-1.asc"))
sink = core.Data()

c.op_decrypt(source, sink)
result = c.op_decrypt_result()
assert not result.unsupported_algorithm, \
    "Unsupported algorithm: {}".format(result.unsupported_algorithm)

support.print_data(sink)

# Idiomatic interface.
with pyme.Context() as c:
    plaintext, _, _ = c.decrypt(open(support.make_filename("cipher-1.asc")))
    assert len(plaintext) > 0
    assert plaintext.find(b'Wenn Sie dies lesen k') >= 0, \
        'Plaintext not found'
