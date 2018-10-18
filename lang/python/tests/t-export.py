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

import gpg
import support

del absolute_import, print_function, unicode_literals

c = gpg.Context()
c.set_armor(True)

sink = gpg.Data()
c.op_export_ext(['Alpha', 'Bob'], 0, sink)
support.print_data(sink)

# Again. Now using a key array.
keys = []
keys.append(c.get_key("0x68697734", False))  # Alpha
keys.append(c.get_key("0xA9E3B0B2", False))  # Bob
sink = gpg.Data()
c.op_export_keys(keys, 0, sink)
support.print_data(sink)
