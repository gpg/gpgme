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
from pyme import core

# known keys
alpha = "A0FF4590BB6122EDEF6E3C542D727CC768697734"
bob = "D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2"
encrypt_only = "F52770D5C4DB41408D918C9F920572769B9FE19C"
sign_only = "7CCA20CCDE5394CEE71C9F0BFED153F12F18F45D"

def make_filename(name):
    return os.path.join(os.environ['top_srcdir'], 'tests', 'gpg', name)

def in_srcdir(name):
    return os.path.join(os.environ['srcdir'], name)

def init_gpgme(proto):
    core.engine_check_version(proto)

verbose = int(os.environ.get('verbose', 0)) > 1
def print_data(data):
    if verbose:
        try:
            # See if it is a file-like object.
            data.seek(0, os.SEEK_SET)
            data = data.read()
        except:
            # Hope for the best.
            pass
        sys.stdout.buffer.write(data)

def mark_key_trusted(ctx, key):
    class Editor(object):
        def __init__(self):
            self.steps = ["trust", "save"]
        def edit(self, status, args, out):
            if args == "keyedit.prompt":
                result = self.steps.pop(0)
            elif args == "edit_ownertrust.value":
                result = "5"
            elif args == "edit_ownertrust.set_ultimate.okay":
                result = "Y"
            elif args == "keyedit.save.okay":
                result = "Y"
            else:
                result = None
            return result
    with core.Data() as sink:
        ctx.op_edit(key, Editor().edit, sink, sink)
