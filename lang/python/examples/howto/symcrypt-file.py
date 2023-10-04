#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, unicode_literals

import gpg
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
# Lesser General Public License along with this program; if not, see
# <https://www.gnu.org/licenses/>.

"""
Symmetrically encrypts a file.  Passphrase will be prompted for via Pinentry.

Will produce both an ASCII armoured and GPG binary format copy of the encrypted
file.
"""

if len(sys.argv) > 2:
    filename = " ".join(sys.argv[1:])
elif len(sys.argv) == 2:
    filename = sys.argv[1]
else:
    filename = input("Enter the path and filename to encrypt: ")

with open(filename, "rb") as f:
    text = f.read()

with gpg.Context(armor=True) as ca:
    try:
        ciphertext, result, sign_result = ca.encrypt(text, passphrase=None,
                                                     sign=False)
        with open("{0}.asc".format(filename), "wb") as fa:
            fa.write(ciphertext)
    except gpg.errors.GPGMEError as e:
        print(e)

with gpg.Context() as cg:
    try:
        ciphertext, result, sign_result = cg.encrypt(text, passphrase=None,
                                                     sign=False)
        with open("{0}.gpg".format(filename), "wb") as fg:
            fg.write(ciphertext)
    except gpg.errors.GPGMEError as e:
        print(e)
