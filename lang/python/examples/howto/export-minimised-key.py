#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, unicode_literals

import gpg
import os.path
import sys

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

print("""
This script exports one or more public keys in minimised form.
""")

c = gpg.Context(armor=True)

if len(sys.argv) >= 4:
    keyfile = sys.argv[1]
    logrus = sys.argv[2]
    homedir = sys.argv[3]
elif len(sys.argv) == 3:
    keyfile = sys.argv[1]
    logrus = sys.argv[2]
    homedir = input("Enter the GPG configuration directory path (optional): ")
elif len(sys.argv) == 2:
    keyfile = sys.argv[1]
    logrus = input("Enter the UID matching the key(s) to export: ")
    homedir = input("Enter the GPG configuration directory path (optional): ")
else:
    keyfile = input("Enter the path and filename to save the secret key to: ")
    logrus = input("Enter the UID matching the key(s) to export: ")
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

try:
    result = c.key_export_minimal(pattern=logrus)
except:
    result = c.key_export_minimal(pattern=None)

if result is not None:
    with open(keyfile, "wb") as f:
        f.write(result)
else:
    pass
