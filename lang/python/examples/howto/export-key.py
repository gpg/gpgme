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
import os
import os.path
import sys

c = gpg.Context(armor=True)
k = gpg.Data()

print("""
This script exports one or more public keys to a file.

If the uer or key IDs are not included then all available public keys will be
exported to a file (ASCII aroured).
""")

if len(sys.argv) > 3:
    filepth = sys.argv[1]
    homedir = sys.argv[2]
    keytext = sys.argv[3]
elif len(sys.argv) == 3:
    filepth = sys.argv[1]
    homedir = sys.argv[2]
    keytext = input("Enter the user or key ID for export: ")
elif len(sys.argv) == 2:
    filepth = sys.argv[1]
    homedir = input("Enter the GPG configuration directory path (optional): ")
    keytext = input("Enter the user or key ID for export: ")
else:
    filepth = input("Enter the filename and path of the key file: ")
    homedir = input("Enter the GPG configuration directory path (optional): ")
    keytext = input("Enter the user or key ID for export (optional): ")

if homedir.startswith("~"):
    if os.path.exists(os.path.expanduser(homedir)) is True:
        c.home_dir = os.path.expanduser(homedir)
    else:
        pass
elif os.path.exists(homedir) is True:
    c.home_dir = homedir
else:
    pass

c.op_export(keytext, 0, k)
k.seek(0, os.SEEK_SET)
expkey = k.read()

with open(filepth, "wb") as f:
    f.write(expkey)
