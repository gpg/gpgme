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

import io
import os
import tempfile
import gpg
import support
_ = support  # to appease pyflakes.

del absolute_import, print_function, unicode_literals

data = gpg.Data('Hello world!')
assert data.read() == b'Hello world!'
assert data.read() == b''

data.seek(0, os.SEEK_SET)
assert data.read() == b'Hello world!'
assert data.read() == b''

data = gpg.Data(b'Hello world!')
assert data.read() == b'Hello world!'

data = gpg.Data(b'Hello world!', copy=False)
assert data.read() == b'Hello world!'

data = gpg.Data()
data.write('Hello world!')
data.seek(0, os.SEEK_SET)
assert data.read() == b'Hello world!'

data = gpg.Data()
data.write(b'Hello world!')
data.seek(0, os.SEEK_SET)
assert data.read() == b'Hello world!'

data = gpg.Data()
data.write(b'Hello world!')
# We expect the second argument to default to SEEK_SET
data.seek(0)
assert data.read() == b'Hello world!'

binjunk = bytes(range(256))
data = gpg.Data()
data.write(binjunk)
data.seek(0, os.SEEK_SET)
assert data.read() == binjunk

data = gpg.Data()
data.set_file_name("foobar")
assert data.get_file_name() == "foobar"

# Test reading from an existing file.
with tempfile.NamedTemporaryFile() as tmp:
    tmp.write(binjunk)
    tmp.flush()
    tmp.seek(0)

    # Open using name.
    data = gpg.Data(file=tmp.name)
    assert data.read() == binjunk

    # Open using name, without copying.
    if False:
        # delayed reads are not yet supported
        data = gpg.Data(file=tmp.name, copy=False)
        assert data.read() == binjunk

    # Open using stream.
    tmp.seek(0)
    data = gpg.Data(file=tmp)
    assert data.read() == binjunk

    # Open using stream, offset, and length.
    data = gpg.Data(file=tmp, offset=0, length=42)
    assert data.read() == binjunk[:42]

    # Open using name, offset, and length.
    data = gpg.Data(file=tmp.name, offset=23, length=42)
    assert data.read() == binjunk[23:23 + 42]


# Test callbacks.
class DataObject(object):
    def __init__(self):
        self.buffer = io.BytesIO()
        self.released = False

    def read(self, amount, hook=None):
        assert not self.released
        return self.buffer.read(amount)

    def write(self, data, hook=None):
        assert not self.released
        return self.buffer.write(data)

    def seek(self, offset, whence, hook=None):
        assert not self.released
        return self.buffer.seek(offset, whence)

    def release(self, hook=None):
        assert not self.released
        self.released = True


do = DataObject()
cookie = object()
data = gpg.Data(cbs=(do.read, do.write, do.seek, do.release, cookie))
data.write('Hello world!')
data.seek(0, os.SEEK_SET)
assert data.read() == b'Hello world!'
del data
assert do.released

# Again, without the cookie.
do = DataObject()
data = gpg.Data(cbs=(do.read, do.write, do.seek, do.release))
data.write('Hello world!')
data.seek(0, os.SEEK_SET)
assert data.read() == b'Hello world!'
del data
assert do.released
