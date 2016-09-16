#!/usr/bin/env python

# Copyright (C) 2005 Igor Belyi <belyi@users.sourceforge.net>
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

import sys
import os
from pyme import core, constants
import support

class KeyEditor(object):
    def __init__(self):
        self.steps = ["fpr", "expire", "1", "primary", "quit"]
        self.step = 0
        self.done = False
        self.verbose = int(os.environ.get('verbose', 0)) > 1

    def edit_fnc(self, status, args, out=None):
        if args == "keyedit.prompt":
            result = self.steps[self.step]
            self.step += 1
        elif args == "keyedit.save.okay":
            result = "Y"
            self.done = self.step == len(self.steps)
        elif args == "keygen.valid":
            result = "0"
        else:
            result = None

        if self.verbose:
            sys.stderr.write("Code: {}, args: {!r}, Returning: {!r}\n"
                             .format(status, args, result))

        return result

support.init_gpgme(constants.PROTOCOL_OpenPGP)

c = core.Context()
c.set_pinentry_mode(constants.PINENTRY_MODE_LOOPBACK)
c.set_passphrase_cb(lambda *args: "abc")
c.set_armor(True)

# The deprecated interface.
editor = KeyEditor()
c.interact(c.get_key("A0FF4590BB6122EDEF6E3C542D727CC768697734", False),
           editor.edit_fnc)
assert editor.done

# The deprecated interface.
sink = core.Data()
editor = KeyEditor()
c.op_edit(c.get_key("A0FF4590BB6122EDEF6E3C542D727CC768697734", False),
          editor.edit_fnc, sink, sink)
assert editor.done
