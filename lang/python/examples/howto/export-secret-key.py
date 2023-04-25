#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, unicode_literals

import gpg
import os
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
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public License and the GNU
# Lesser General Public along with this program; if not, see
# <https://www.gnu.org/licenses/>.

print("""
This script exports one or more secret keys.

The gpg-agent and pinentry are invoked to authorise the export.
""")

def open_0o600(path, flags):
    return os.open(path, flags, mode=0o600)

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
    logrus = input("Enter the UID matching the secret key(s) to export: ")
    homedir = input("Enter the GPG configuration directory path (optional): ")
else:
    keyfile = input("Enter the path and filename to save the secret key to: ")
    logrus = input("Enter the UID matching the secret key(s) to export: ")
    homedir = input("Enter the GPG configuration directory path (optional): ")

if len(homedir) == 0:
    homedir = None
elif homedir.startswith("~"):
    userdir = os.path.expanduser(homedir)
    if os.path.exists(userdir) is True:
        homedir = os.path.realpath(userdir)
    else:
        homedir = None
else:
    homedir = os.path.realpath(homedir)

if homedir is not None and os.path.exists(homedir) is False:
    homedir = None
elif homedir is not None and os.path.exists(homedir) is True:
    if os.path.isdir(homedir) is False:
        homedir = None
    else:
        pass

if homedir is not None:
    c.home_dir = homedir
else:
    pass

try:
    result = c.key_export_secret(pattern=logrus)
except:
    result = c.key_export_secret(pattern=None)

if result is not None:
    with open(keyfile, "wb", opener=open_0o600) as f:
        f.write(result)
else:
    pass
