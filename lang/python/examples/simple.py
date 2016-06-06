#!/usr/bin/env python3
# Copyright (C) 2005 Igor Belyi <belyi@users.sourceforge.net>
# Copyright (C) 2002 John Goerzen <jgoerzen@complete.org>
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
from pyme import core, errors

core.check_version(None)

# Set up our input and output buffers.

plain = core.Data('This is my message.')
cipher = core.Data()

# Initialize our context.

c = core.Context()
c.set_armor(1)

# Set up the recipients.

sys.stdout.write("Enter name of your recipient: ")
sys.stdout.flush()
name = sys.stdin.readline().strip()
c.op_keylist_start(name, 0)
r = c.op_keylist_next()

if r == None:
    print("The key for user \"%s\" was not found" % name)
else:
    # Do the encryption.
    try:
        c.op_encrypt([r], 1, plain, cipher)
        cipher.seek(0, os.SEEK_SET)
        sys.stdout.buffer.write(cipher.read())
    except errors.GPGMEError as ex:
        print(ex.getstring())
