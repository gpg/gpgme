#!/usr/bin/env python
#
# Copyright (C) 2016 g10 Code GmbH
# Copyright (C) 2008 Bernhard Reiter <bernhard@intevation.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

"""A test applicaton for the CMS protocol."""

from __future__ import absolute_import, print_function, unicode_literals
del absolute_import, print_function, unicode_literals

import sys
import pyme

if len(sys.argv) != 2:
    sys.exit("fingerprint or unique key ID for gpgme_get_key()")

with pyme.Context(protocol=pyme.constants.PROTOCOL_CMS) as c:
    key = c.get_key(sys.argv[1], False)

    print("got key: ", key.subkeys[0].fpr)
    for uid in key.uids:
        print(uid.uid)
