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

import os
import gpg
import support
_ = support  # to appease pyflakes.

del absolute_import, print_function, unicode_literals

testname = "abcde12345"

c = gpg.Context()
c.set_armor(True)

source = gpg.Data("Hallo Leute\n")
source.set_file_name(testname)
cipher = gpg.Data()
plain = gpg.Data()

keys = []
keys.append(c.get_key("A0FF4590BB6122EDEF6E3C542D727CC768697734", False))

c.op_encrypt(keys, gpg.constants.ENCRYPT_ALWAYS_TRUST, source, cipher)
cipher.seek(0, os.SEEK_SET)
c.op_decrypt(cipher, plain)
result = c.op_decrypt_result()
assert result.file_name == testname
