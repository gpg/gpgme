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
import subprocess
import pyme
import support
support.init_gpgme(pyme.constants.PROTOCOL_OpenPGP)

subprocess.check_call([os.path.join(os.getenv('top_srcdir'),
                                    "tests", "start-stop-agent"), "--start"])

with pyme.Context() as c:
    alpha = c.get_key("A0FF4590BB6122EDEF6E3C542D727CC768697734", False)
    bob = c.get_key("D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2", False)

    # Mark alpha as trusted.  The signature verification tests expect
    # this.
    support.mark_key_trusted(c, alpha)

    c.op_import(open(support.in_srcdir("encrypt-only.asc")))
    c.op_import(open(support.in_srcdir("sign-only.asc")))
