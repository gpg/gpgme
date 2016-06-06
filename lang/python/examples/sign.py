#!/usr/bin/env python3
# Copyright (C) 2002 John Goerzen
# <jgoerzen@complete.org>
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
from pyme import core, callbacks
from pyme.constants.sig import mode

core.check_version(None)

plain = core.Data(b"Test message")
sig = core.Data()
c = core.Context()
c.set_passphrase_cb(callbacks.passphrase_stdin, b'for signing')
c.op_sign(plain, sig, mode.CLEAR)
sig.seek(0, os.SEEK_SET)
sys.stdout.buffer.write(sig.read())
