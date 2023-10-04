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
Signs and encrypts a file to a specified key.  If entering both the key and the
filename on the command line, the key must be entered first.

Signs with and also encrypts to the default key of the user invoking the
script.  Will treat all recipients as trusted to permit encryption.

Will produce both an ASCII armoured and GPG binary format copy of the signed
and encrypted file.
"""

if len(sys.argv) > 3:
    a_key = sys.argv[1]
    filename = " ".join(sys.argv[2:])
elif len(sys.argv) == 3:
    a_key = sys.argv[1]
    filename = sys.argv[2]
elif len(sys.argv) == 2:
    a_key = sys.argv[1]
    filename = input("Enter the path and filename to encrypt: ")
else:
    a_key = input("Enter the fingerprint or key ID to encrypt to: ")
    filename = input("Enter the path and filename to encrypt: ")

rkey = list(gpg.Context().keylist(pattern=a_key, secret=False))
with open(filename, "rb") as f:
    text = f.read()

with gpg.Context(armor=True) as ca:
    ciphertext, result, sign_result = ca.encrypt(text, recipients=rkey,
                                                 always_trust=True,
                                                 add_encrypt_to=True)
    with open("{0}.asc".format(filename), "wb") as fa:
        fa.write(ciphertext)

with gpg.Context() as cg:
    ciphertext, result, sign_result = cg.encrypt(text, recipients=rkey,
                                                 always_trust=True,
                                                 add_encrypt_to=True)
    with open("{0}.gpg".format(filename), "wb") as fg:
        fg.write(ciphertext)
