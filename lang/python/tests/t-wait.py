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

import time
import gpg
import support
_ = support  # to appease pyflakes.

del absolute_import, print_function, unicode_literals

c = gpg.Context()
c.set_armor(True)

# Checking a message without a signature.
sig = gpg.Data("foo\n")
text = gpg.Data()
c.op_verify_start(sig, None, text)

try:
    while True:
        err = c.wait(False)
        if err:
            break
        time.sleep(0.1)
except Exception as e:
    assert e.getcode() == gpg.errors.NO_DATA
else:
    assert False, "Expected an error, got none"
