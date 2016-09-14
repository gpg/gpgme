#!/usr/bin/env python
#
# Copyright (C) 2016 g10 Code GmbH
# Copyright (C) 2005 Igor Belyi <belyi@users.sourceforge.net>
# Copyright (C) 2002 John Goerzen <jgoerzen@complete.org>
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

from __future__ import absolute_import, print_function, unicode_literals
del absolute_import, print_function, unicode_literals

import sys
import pyme

with pyme.Context(armor=True) as c:
    recipients = []
    print("Enter name of your recipient(s), end with a blank line.")
    while True:
        line = input()
        if not line:
            break
        new = list(c.keylist(line))
        if not new:
            print("Matched no known keys.")
        else:
            print("Adding {}.".format(", ".join(k.uids[0].name for k in new)))
            recipients.extend(new)

    if not recipients:
        sys.exit("No recipients.")

    print("Encrypting for {}.".format(", ".join(k.uids[0].name
                                                for k in recipients)))

    ciphertext, _, _ = c.encrypt(b"This is my message,", recipients)
    sys.stdout.buffer.write(ciphertext)
