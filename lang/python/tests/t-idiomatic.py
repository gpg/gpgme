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
import tempfile
from pyme import core, constants, errors
import support

support.init_gpgme(constants.PROTOCOL_OpenPGP)
c = core.Context()

# Demonstrate automatic wrapping of file-like objects with 'fileno'
# method.
with tempfile.TemporaryFile() as source, \
     tempfile.TemporaryFile() as signed, \
     tempfile.TemporaryFile() as sink:
    source.write(b"Hallo Leute\n")
    source.seek(0, os.SEEK_SET)

    c.op_sign(source, signed, constants.SIG_MODE_NORMAL)
    signed.seek(0, os.SEEK_SET)
    c.op_verify(signed, None, sink)
    result = c.op_verify_result()

    assert len(result.signatures) == 1, "Unexpected number of signatures"
    sig = result.signatures[0]
    assert sig.summary == 0
    assert errors.GPGMEError(sig.status).getcode() == errors.NO_ERROR

    sink.seek(0, os.SEEK_SET)
    assert sink.read() == b"Hallo Leute\n"
