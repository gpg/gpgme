#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, unicode_literals

# Copyright (C) 2018 Ben McGinnes <ben@gnupg.org>
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License and the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public License and the GNU
# Lesser General Public License along with this program; if not, see
# <https://www.gnu.org/licenses/>.

import gpg
import os.path

print("""
This script revokes a user ID on an existing key.

The gpg-agent and pinentry are invoked to enter the passphrase.
""")

c = gpg.Context()

homedir = input("Enter the GPG configuration directory path (optional): ")
fpr0 = input("Enter the fingerprint of the key to modify: ")
uid_name = input("Enter the name of the user ID: ")
uid_email = input("Enter the email address of the user ID: ")
uid_cmnt = input("Enter a comment to include (optional): ")

if homedir.startswith("~"):
    if os.path.exists(os.path.expanduser(homedir)) is True:
        c.home_dir = os.path.expanduser(homedir)
    else:
        pass
elif os.path.exists(homedir) is True:
    c.home_dir = homedir
else:
    pass

fpr = "".join(fpr0.split())

if uid_cmnt:
    userid = "{0} ({1}) <{2}>".format(uid_name, uid_cmnt, uid_email)
else:
    userid = "{0} <{2}>".format(uid_name, uid_email)

key = c.get_key(fpr, secret=True)
c.key_revoke_uid(key, userid)
