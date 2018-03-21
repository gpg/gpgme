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
import sys

from groups import group_lists

"""
Signs and encrypts a file to a specified group of keys.  If entering both the
group and the filename on the command line, the group must be entered first.

Signs with and also encrypts to the default key of the user invoking the
script.  Will treat all recipients as trusted to permit encryption.

Will produce both an ASCII armoured and GPG binary format copy of the signed
and encrypted file.
"""

if len(sys.argv) > 3:
    group = sys.argv[1]
    filename = " ".join(sys.argv[2:])
elif len(sys.argv) == 3:
    group = sys.argv[1]
    filename = sys.argv[2]
elif len(sys.argv) == 2:
    group = sys.argv[1]
    filename = input("Enter the path and filename to encrypt: ")
else:
    group = input("Enter the name of the group to select keys for: ")
    filename = input("Enter the path and filename to encrypt: ")

keys = []
a = []

for i in range(len(group_lists)):
    a.append(group_lists[i][0])

b = a.index(group)

for i in range(len(group_lists[b][1])):
    logrus = group_lists[b][1][i]
    keys.append(gpg.Context().keylist(pattern=logrus))

with open(filename, "rb") as f:
    text = f.read()

with gpg.Context(armor=True) as ca:
    ciphertext, result, sign_result = ca.encrypt(text, recipients=keys,
                                                 always_trust=True,
                                                     add_encrypt_to=True)
    with open("{0}.asc".format(filename), "wb") as fa:
        fa.write(ciphertext)

with gpg.Context() as cg:
    ciphertext, result, sign_result = cg.encrypt(text, recipients=keys,
                                                 always_trust=True,
                                                     add_encrypt_to=True)
    with open("{0}.gpg".format(filename), "wb") as fg:
        fg.write(ciphertext)
