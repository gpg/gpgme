#!/usr/bin/env python3
#
# Copyright (C) 2016 g10 Code GmbH
# Copyright (C) 2005 Igor Belyi <belyi@users.sourceforge.net>
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

"""Simple interactive editor to test editor scripts"""

import sys
import pyme
import pyme.constants.status

# Get names for the status codes
status2str = {}
for name in dir(pyme.constants.status):
    if not name.startswith('__') and name != "util":
        status2str[getattr(pyme.constants.status, name)] = name

if len(sys.argv) != 2:
    sys.exit("Usage: %s <Gpg key pattern>\n" % sys.argv[0])

name = sys.argv[1]

with pyme.Context() as c:
    keys = list(c.keylist(name))
    if len(keys) == 0:
        sys.exit("No key matching {}.".format(name))
    if len(keys) > 1:
        sys.exit("More than one key matching {}.".format(name))

    key = keys[0]
    print("Editing key {} ({}):".format(key.uids[0].uid, key.subkeys[0].fpr))

    def edit_fnc(status, args):
        print("Status: {} ({}), args: {} > ".format(
            status2str[status], status, args), end='', flush=True)

        if not 'GET' in status2str[status]:
            # no prompt
            print()
            return None

        try:
            return input()
        except EOFError:
            return "quit"

    c.op_edit(key, edit_fnc, None, sys.stdout)
