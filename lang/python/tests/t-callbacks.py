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



# Test the progress callback.
parms = """<GnupgKeyParms format="internal">
Key-Type: RSA
Key-Length: 1024
Name-Real: Joe Tester
Name-Comment: with stupid passphrase
Name-Email: joe+pyme@example.org
Passphrase: Crypt0R0cks
Expire-Date: 2020-12-31
</GnupgKeyParms>
"""

messages = []
def progress_cb(what, typ, current, total, hook=None):
    assert hook == messages
    messages.append(
        "PROGRESS UPDATE: what = {}, type = {}, current = {}, total = {}"
        .format(what, typ, current, total))

c = core.Context()
c.set_progress_cb(progress_cb, messages)
c.op_genkey(parms, None, None)
assert len(messages) > 0

# Test exception handling.
def progress_cb(what, typ, current, total, hook=None):
    raise myException

c = core.Context()
c.set_progress_cb(progress_cb, None)
try:
    c.op_genkey(parms, None, None)
except Exception as e:
    assert e == myException
else:
    assert False, "Expected an error, got none"
