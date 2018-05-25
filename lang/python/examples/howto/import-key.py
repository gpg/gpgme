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
# Lesser General Public Licensefor more details.
#
# You should have received a copy of the GNU General Public License and the GNU
# Lesser General Public along with this program; if not, see
# <http://www.gnu.org/licenses/>.

import gpg
import os.path
import sys

c = gpg.Context(armor=True)

print("""
This script imports a public key into the public keybox/keyring from a file.
""")

if len(sys.argv) >= 3:
    filepth = sys.argv[1]
    homedir = sys.argv[2]
elif len(sys.argv) == 2:
    filepth = sys.argv[1]
    homedir = input("Enter the GPG configuration directory path (optional): ")
else:
    filepth = input("Enter the filename and path of the key file: ")
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

with open(filepth, "rb") as f:
    incoming = f.read()

c.op_import(incoming)
res = c.op_import_result()

result = """
Imported {0} of {1} keys with:

  {2} new revocations
  {3} new signatures
  {4} new sub keys
  {5} new user IDs
  {6} new secret keys
  {7} unchanged keys
""".format(res.imported, res.considered, res.new_revocations,
           res.new_signatures, res.new_sub_keys, res.new_user_ids,
           res.secret_imported, res.unchanged)
print(res)
