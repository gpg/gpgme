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

testname = "abcde12345"

support.init_gpgme(constants.PROTOCOL_OpenPGP)
c = core.Context()
c.set_armor(True)

source = core.Data("Hallo Leute\n")
source.set_file_name(testname)
cipher = core.Data()
plain = core.Data()

keys = []
keys.append(c.get_key("A0FF4590BB6122EDEF6E3C542D727CC768697734", False))

c.op_encrypt(keys, constants.ENCRYPT_ALWAYS_TRUST, source, cipher)
cipher.seek(0, os.SEEK_SET)
c.op_decrypt(cipher, plain)
result = c.op_decrypt_result()
assert result.file_name == testname
