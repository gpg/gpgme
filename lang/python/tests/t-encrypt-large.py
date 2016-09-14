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
import random
from pyme import core, constants
import support

if len(sys.argv) == 2:
    nbytes = int(sys.argv[1])
else:
    nbytes = 100000

support.init_gpgme(constants.PROTOCOL_OpenPGP)
c = core.Context()

ntoread = nbytes
def read_cb(amount):
    global ntoread
    chunk = ntoread if ntoread < amount else amount
    ntoread -= chunk
    assert ntoread >= 0
    assert chunk >= 0
    return bytes(bytearray(random.randrange(256) for i in range(chunk)))

nwritten = 0
def write_cb(data):
    global nwritten
    nwritten += len(data)
    return len(data)

source = core.Data(cbs=(read_cb, None, None, lambda: None))
sink = core.Data(cbs=(None, write_cb, None, lambda: None))

keys = []
keys.append(c.get_key("A0FF4590BB6122EDEF6E3C542D727CC768697734", False))
keys.append(c.get_key("D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2", False))

c.op_encrypt(keys, constants.ENCRYPT_ALWAYS_TRUST, source, sink)
result = c.op_encrypt_result()
assert not result.invalid_recipients, \
    "Invalid recipient encountered: {}".format(result.invalid_recipients.fpr)
assert ntoread == 0

if support.verbose:
    sys.stderr.write(
        "plaintext={} bytes, ciphertext={} bytes\n".format(nbytes, nwritten))
