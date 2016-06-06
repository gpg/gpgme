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
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

import sys
import os
from pyme import core
from pyme.core import Data, Context

core.check_version(None)

class KeyEditor:
    def __init__(self):
        self.steps = ["fpr", "expire", "1", "primary", "quit"]
        self.step = 0

    def edit_fnc(self, status, args, out):
        print("[-- Response --]")
        out.seek(0, os.SEEK_SET)
        sys.stdout.buffer.write(out.read())
        print("[-- Code: %d, %s --]" % (status, args))

        if args == "keyedit.prompt":
            result = self.steps[self.step]
            self.step += 1
        elif args == "keyedit.save.okay":
            result = "Y"
        elif args == "keygen.valid":
            result = "0"
        else:
            result = None

        return result

if not os.getenv("GNUPGHOME"):
    print("Please, set GNUPGHOME env.var. pointing to GPGME's tests/gpg dir")
else:
    c = Context()
    c.set_passphrase_cb(lambda x,y,z: "abc")
    out = Data()
    c.op_keylist_start(b"Alpha", 0)
    key = c.op_keylist_next()
    if not key:
        sys.exit("Key Alpha not found.  " +
                 "Did you point GNUPGHOME to GPGME's tests/gpg dir?")
    c.op_edit(key, KeyEditor().edit_fnc, out, out)
    print("[-- Last response --]")
    out.seek(0, os.SEEK_SET)
    sys.stdout.buffer.write(out.read())
