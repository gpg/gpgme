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
import sys

"""
Signs a file with a specified key.  If entering both the key and the filename
on the command line, the key must be entered first.

Will produce both an ASCII armoured and GPG binary format copy of the detached
signature file.
"""

if len(sys.argv) > 3:
    logrus = sys.argv[1]
    filename = " ".join(sys.argv[2:])
elif len(sys.argv) == 3:
    logrus = sys.argv[1]
    filename = sys.argv[2]
elif len(sys.argv) == 2:
    logrus = sys.argv[1]
    filename = input("Enter the path and filename to sign: ")
else:
    logrus = input("Enter the fingerprint or key ID to sign with: ")
    filename = input("Enter the path and filename to sign: ")

with open(filename, "rb") as f:
    text = f.read()

key = list(gpg.Context().keylist(pattern=logrus))

with gpg.Context(armor=True, signers=key) as ca:
    signed_data, result = ca.sign(text, mode=gpg.constants.sig.mode.DETACH)
    with open("{0}.asc".format(filename), "wb") as fa:
        fa.write(signed_data)

with gpg.Context(signers=key) as cb:
    signed_data, result = cb.sign(text, mode=gpg.constants.sig.mode.DETACH)
    with open("{0}.sig".format(filename), "wb") as fb:
        fb.write(signed_data)
