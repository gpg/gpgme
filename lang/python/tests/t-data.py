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

from pyme import core

data = core.Data('Hello world!')
assert data.read() == b'Hello world!'
assert data.read() == b''

data.seek(0, os.SEEK_SET)
assert data.read() == b'Hello world!'
assert data.read() == b''

data = core.Data(b'Hello world!')
assert data.read() == b'Hello world!'

data = core.Data()
data.write('Hello world!')
data.seek(0, os.SEEK_SET)
assert data.read() == b'Hello world!'

data = core.Data()
data.write(b'Hello world!')
data.seek(0, os.SEEK_SET)
assert data.read() == b'Hello world!'

binjunk = bytes(range(256))
data = core.Data()
data.write(binjunk)
data.seek(0, os.SEEK_SET)
assert data.read() == binjunk
