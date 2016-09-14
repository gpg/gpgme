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


# Test the edit callback.
c = core.Context()
c.set_pinentry_mode(constants.PINENTRY_MODE_LOOPBACK)
c.set_passphrase_cb(lambda *args: "abc")
sink = core.Data()
alpha = c.get_key("A0FF4590BB6122EDEF6E3C542D727CC768697734", False)

cookie = object()
edit_cb_called = False
def edit_cb(status, args, hook):
    global edit_cb_called
    edit_cb_called = True
    assert hook == cookie
    return "quit" if args == "keyedit.prompt" else None
c.op_edit(alpha, edit_cb, cookie, sink)
assert edit_cb_called

# Test exceptions.
c = core.Context()
c.set_pinentry_mode(constants.PINENTRY_MODE_LOOPBACK)
c.set_passphrase_cb(lambda *args: "abc")
sink = core.Data()

def edit_cb(status, args):
    raise myException
try:
    c.op_edit(alpha, edit_cb, None, sink)
except Exception as e:
    assert e == myException
else:
    assert False, "Expected an error, got none"



# Test the status callback.
source = core.Data("Hallo Leute\n")
sink = core.Data()

status_cb_called = False
def status_cb(keyword, args, hook=None):
    global status_cb_called
    status_cb_called = True
    assert hook == cookie

c = core.Context()
c.set_status_cb(status_cb, cookie)
c.set_ctx_flag("full-status", "1")
c.op_encrypt([alpha], constants.ENCRYPT_ALWAYS_TRUST, source, sink)
assert status_cb_called

# Test exceptions.
source = core.Data("Hallo Leute\n")
sink = core.Data()

def status_cb(keyword, args):
    raise myException

c = core.Context()
c.set_status_cb(status_cb, None)
c.set_ctx_flag("full-status", "1")
try:
    c.op_encrypt([alpha], constants.ENCRYPT_ALWAYS_TRUST, source, sink)
except Exception as e:
    assert e == myException
else:
    assert False, "Expected an error, got none"



# Test the data callbacks.
def read_cb(amount, hook=None):
    assert hook == cookie
    return 0
def release_cb(hook=None):
    assert hook == cookie
data = core.Data(cbs=(read_cb, None, None, release_cb, cookie))
try:
    data.read()
except Exception as e:
    assert type(e) == TypeError
else:
    assert False, "Expected an error, got none"

def read_cb(amount):
    raise myException
data = core.Data(cbs=(read_cb, None, None, lambda: None))
try:
    data.read()
except Exception as e:
    assert e == myException
else:
    assert False, "Expected an error, got none"


def write_cb(what, hook=None):
    assert hook == cookie
    return "wrong type"
data = core.Data(cbs=(None, write_cb, None, release_cb, cookie))
try:
    data.write(b'stuff')
except Exception as e:
    assert type(e) == TypeError
else:
    assert False, "Expected an error, got none"

def write_cb(what):
    raise myException
data = core.Data(cbs=(None, write_cb, None, lambda: None))
try:
    data.write(b'stuff')
except Exception as e:
    assert e == myException
else:
    assert False, "Expected an error, got none"


def seek_cb(offset, whence, hook=None):
    assert hook == cookie
    return "wrong type"
data = core.Data(cbs=(None, None, seek_cb, release_cb, cookie))
try:
    data.seek(0, os.SEEK_SET)
except Exception as e:
    assert type(e) == TypeError
else:
    assert False, "Expected an error, got none"

def seek_cb(offset, whence):
    raise myException
data = core.Data(cbs=(None, None, seek_cb, lambda: None))
try:
    data.seek(0, os.SEEK_SET)
except Exception as e:
    assert e == myException
else:
    assert False, "Expected an error, got none"
