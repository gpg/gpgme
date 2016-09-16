#!/usr/bin/env python
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

from __future__ import absolute_import, print_function, unicode_literals
del absolute_import, print_function, unicode_literals

import sys
import pyme

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

    def edit_fnc(keyword, args):
        print("Status: {} ({}), args: {} > ".format(
            keyword, status, args), end='', flush=True)

        if not 'GET' in keyword:
            # no prompt
            print()
            return None

        try:
            return input()
        except EOFError:
            return "quit"

    c.interact(key, edit_fnc, sink=sys.stdout)
