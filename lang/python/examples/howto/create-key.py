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
This script generates a new key which does not expire.

The gpg-agent and pinentry are invoked to set the passphrase.
""")

c = gpg.Context()

homedir = input("Enter the GPG configuration directory path (optional): ")
uid_name = input("Enter the name of the user ID: ")
uid_email = input("Enter the email address of the user ID: ")
uid_cmnt = input("Enter a comment to include (optional): ")
key_algo = input("Enter the key algorithm, RSA or DSA (default is RSA): ")
key_size = input("Enter the key size (2048-4096, default is 2048): ")

if homedir.startswith("~"):
    if os.path.exists(os.path.expanduser(homedir)) is True:
        c.home_dir = os.path.expanduser(homedir)
    else:
        pass
elif os.path.exists(homedir) is True:
    c.home_dir = homedir
else:
    pass

if uid_cmnt:
    userid = "{0} ({1}) <{2}>".format(uid_name, uid_cmnt, uid_email)
else:
    userid = "{0} <{2}>".format(uid_name, uid_email)

if key_algo.lower() == "dsa":
    ka = "dsa"
else:
    ka = "rsa"

if len(key_size) == 4:
    try:
        ks0 = int(key_size)
    except ValueError:
        ks0 = None
    if ks0 is None:
        ks = "2048"
    else:
        if ks0 < 2048:
            ks = "2048"
        elif ka == "dsa" and ks0 > 3072:
            ks = "3072"
        elif ka == "rsa" and ks0 > 4096:
            ks = "4096"
        else:
            ks = key_size
else:
    ks = "2048"

keyalgo = "{0}{1}".format(ka, ks)

newkey = c.create_key(userid, algorithm=keyalgo, expires=False,
                      passphrase=True, certify=True)
key = c.get_key(newkey.fpr, secret=True)

if ka == "rsa":
    newsub = c.create_subkey(key, algorithm=keyalgo, expires=False,
                             passphrase=True, encrypt=True)
else:
    newsub = c.create_subkey(key, expires=False, passphrase=True,
                             encrypt=True)
