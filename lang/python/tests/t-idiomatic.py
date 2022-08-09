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

import sys
import io
import os
import tempfile
import gpg
import support
_ = support  # to appease pyflakes.

del absolute_import, print_function, unicode_literals

# Both Context and Data can be used as context manager:
with gpg.Context() as c, gpg.Data() as d:
    c.get_engine_info()
    d.write(b"Halloechen")
    leak_c = c
    leak_d = d

leak_c.__del__()
leak_d.__del__()
assert leak_c.wrapped is None
assert leak_d.wrapped is None


def sign_and_verify(source, signed, sink):
    with gpg.Context() as c:
        c.op_sign(source, signed, gpg.constants.sig.mode.NORMAL)
        signed.seek(0, os.SEEK_SET)
        c.op_verify(signed, None, sink)
        result = c.op_verify_result()

    assert len(result.signatures) == 1, "Unexpected number of signatures"
    sig = result.signatures[0]
    assert sig.summary == (gpg.constants.sigsum.VALID |
                           gpg.constants.sigsum.GREEN)
    assert gpg.errors.GPGMEError(sig.status).getcode() == gpg.errors.NO_ERROR

    sink.seek(0, os.SEEK_SET)
    assert sink.read() == b"Hallo Leute\n"


# Demonstrate automatic wrapping of file-like objects with 'fileno'
# method.
with tempfile.TemporaryFile() as source, \
     tempfile.TemporaryFile() as signed, \
     tempfile.TemporaryFile() as sink:
    source.write(b"Hallo Leute\n")
    source.seek(0, os.SEEK_SET)

    sign_and_verify(source, signed, sink)

if sys.version_info[0] == 3:
    # Python2's io.BytesIO does not implement the buffer interface,
    # hence we cannot use it as sink.

    # XXX: Python's io.BytesIo.truncate does not work as advertised.
    # https://bugs.python.org/issue27261
    bio = io.BytesIO()
    bio.truncate(1)
    if len(bio.getvalue()) != 1:
        # This version of Python is affected, preallocate buffer.
        preallocate = 128 * b'\x00'
    else:
        preallocate = b''

    # Demonstrate automatic wrapping of objects implementing the buffer
    # interface, and the use of data objects with the 'with' statement.
    with io.BytesIO(preallocate) as signed, gpg.Data() as sink:
        sign_and_verify(b"Hallo Leute\n", signed, sink)
