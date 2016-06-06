#!/usr/bin/env python3
# Copyright (C) 2005 Igor Belyi <belyi@users.sourceforge.net>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
#    02111-1307 USA

import sys
from pyme import core
from pyme.core import Data, Context
from pyme.constants import status

core.check_version(None)

# Get names for the status codes
stat2str = {}
for name in dir(status):
    if not name.startswith('__') and name != "util":
        stat2str[getattr(status, name)] = name


# Print the output received since the last prompt before giving the new prompt
def edit_fnc(stat, args, helper):
    global stat_strings
    try:
        while True:
            helper["data"].seek(helper["skip"], 0)
            data = helper["data"].read()
            helper["skip"] += len(data)
            sys.stdout.buffer.write(data)
            return input("(%s) %s > " % (stat2str[stat], args))
    except EOFError:
        pass

# Simple interactive editor to test editor scripts
if len(sys.argv) != 2:
    sys.stderr.write("Usage: %s <Gpg key pattern>\n" % sys.argv[0])
else:
    c = Context()
    out = Data()
    c.op_keylist_start(sys.argv[1], 0)
    key = c.op_keylist_next()
    helper = {"skip": 0, "data": out}
    c.op_edit(key, edit_fnc, helper, out)
    print("[-- Final output --]")
    out.seek(helper["skip"], 0)
    sys.stdout.buffer.write(out.read())
