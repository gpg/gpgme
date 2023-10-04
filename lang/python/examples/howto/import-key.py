#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, unicode_literals

import gpg
import os.path
import sys

del absolute_import, division, unicode_literals

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

print("""
This script imports one or more public keys from a single file.
""")

c = gpg.Context(armor=True)

if len(sys.argv) >= 3:
    keyfile = sys.argv[1]
    homedir = sys.argv[2]
elif len(sys.argv) == 2:
    keyfile = sys.argv[1]
    homedir = input("Enter the GPG configuration directory path (optional): ")
else:
    keyfile = input("Enter the path and filename to import the key(s) from: ")
    homedir = input("Enter the GPG configuration directory path (optional): ")

if homedir.startswith("~"):
    if os.path.exists(os.path.expanduser(homedir)) is True:
        c.home_dir = os.path.expanduser(homedir)
    else:
        pass
elif os.path.exists(homedir) is True:
    c.home_dir = homedir
else:
    pass

if os.path.isfile(keyfile) is True:
    with open(keyfile, "rb") as f:
        incoming = f.read()
    result = c.key_import(incoming)
else:
    result = None

if result is not None and hasattr(result, "considered") is False:
    print(result)
elif result is not None and hasattr(result, "considered") is True:
    num_keys = len(result.imports)
    new_revs = result.new_revocations
    new_sigs = result.new_signatures
    new_subs = result.new_sub_keys
    new_uids = result.new_user_ids
    new_scrt = result.secret_imported
    nochange = result.unchanged
    print("""
The total number of keys considered for import was:  {0}

   Number of keys revoked:  {1}
 Number of new signatures:  {2}
    Number of new subkeys:  {3}
   Number of new user IDs:  {4}
Number of new secret keys:  {5}
 Number of unchanged keys:  {6}

The key IDs for all considered keys were:
""".format(num_keys, new_revs, new_sigs, new_subs, new_uids, new_scrt,
           nochange))
    for i in range(num_keys):
        print(result.imports[i].fpr)
    print("")
elif result is None:
    print("You must specify a key file to import.")
