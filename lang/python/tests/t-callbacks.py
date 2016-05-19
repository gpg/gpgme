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
from pyme import core, constants
import support

support.init_gpgme(constants.PROTOCOL_OpenPGP)

c = core.Context()
c.set_pinentry_mode(constants.PINENTRY_MODE_LOOPBACK)

source = core.Data("Hallo Leute\n")
sink = core.Data()

# Valid passphrases, both as string and bytes.
for passphrase in ('foo', b'foo'):
    def passphrase_cb(hint, desc, prev_bad, hook=None):
        assert hook == passphrase
        return hook

    c.set_passphrase_cb(passphrase_cb, passphrase)
    c.op_encrypt([], 0, source, sink)

# Returning an invalid type.
def passphrase_cb(hint, desc, prev_bad, hook=None):
    return 0

c.set_passphrase_cb(passphrase_cb, None)
try:
    c.op_encrypt([], 0, source, sink)
except Exception as e:
    assert type(e) == TypeError
    assert str(e) == "expected str or bytes from passphrase callback, got int"
else:
    assert False, "Expected an error, got none"

# Raising an exception inside callback.
myException = Exception()
def passphrase_cb(hint, desc, prev_bad, hook=None):
    raise myException

c.set_passphrase_cb(passphrase_cb, None)
try:
    c.op_encrypt([], 0, source, sink)
except Exception as e:
    assert e == myException
else:
    assert False, "Expected an error, got none"

# Wrong kind of callback function.
def bad_passphrase_cb():
    pass

c.set_passphrase_cb(bad_passphrase_cb, None)
try:
    c.op_encrypt([], 0, source, sink)
except Exception as e:
    assert type(e) == TypeError
else:
    assert False, "Expected an error, got none"
