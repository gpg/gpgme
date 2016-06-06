#!/usr/bin/env python3
# Copyright (C) 2008 Igor Belyi <belyi@users.sourceforge.net>
# Copyright (C) 2002 John Goerzen <jgoerzen@complete.org>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of the GNU General Public License as
#    published by the Free Software Foundation; either version 2 of
#    the License, or (at your option) any later version.
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

"""
This program will try to encrypt a simple message to each key on your
keyring.  If your keyring has any invalid keys on it, those keys will
be skipped and it will re-try the encryption."""

import sys
import os
from pyme import core
from pyme.core import Data, Context

core.check_version(None)

plain = Data('This is my message.')

c = Context()
c.set_armor(1)

def sendto(keylist):
    cipher = Data()
    c.op_encrypt(keylist, 1, plain, cipher)
    cipher.seek(0, os.SEEK_SET)
    return cipher.read()

names = []
for key in c.op_keylist_all(None, 0):
    try:
        print(" *** Found key for %s" % key.uids[0].uid)
        valid = 0
        for subkey in key.subkeys:
            keyid = subkey.keyid
            if keyid is None:
                break
            can_encrypt = subkey.can_encrypt
            valid += can_encrypt
            print("     Subkey %s: encryption %s" %
                  (keyid, can_encrypt and "enabled" or "disabled"))
    except UnicodeEncodeError as e:
        print(e)

    if valid:
        names.append(key)
    else:
        print("     This key cannot be used for encryption; skipping.")

passno = 0

print("Encrypting to %d recipients" % len(names))
sys.stdout.buffer.write(sendto(names))
