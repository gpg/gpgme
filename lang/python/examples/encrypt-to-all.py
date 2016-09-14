#!/usr/bin/env python
#
# Copyright (C) 2016 g10 Code GmbH
# Copyright (C) 2008 Igor Belyi <belyi@users.sourceforge.net>
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

"""
This program will try to encrypt a simple message to each key on your
keyring.  If your keyring has any invalid keys on it, those keys will
be skipped and it will re-try the encryption."""

from __future__ import absolute_import, print_function, unicode_literals
del absolute_import, print_function, unicode_literals

import sys
import pyme

with pyme.Context(armor=True) as c:
    recipients = list()
    for key in c.keylist():
        valid = 0
        if any(sk.can_encrypt for sk in key.subkeys):
            recipients.append(key)
            print("Adding recipient {0}.".format(key.uids[0].uid))

    ciphertext = None
    while not ciphertext:
        print("Encrypting to %d recipients" % len(recipients))
        try:
            ciphertext, _, _ = c.encrypt(b'This is my message.',
                                         recipients=recipients)
        except pyme.errors.InvalidRecipients as e:
            print("Encryption failed for these keys:\n{0!s}".format(e))

            # filter out the bad keys
            bad_keys = {bad.fpr for bad in e.recipients}
            recipients = [r for r in recipients
                          if not r.subkeys[0].fpr in bad_keys]

    sys.stdout.buffer.write(ciphertext)
