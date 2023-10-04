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
import time

"""
Verifies a signed file which has been signed with either NORMAL or CLEAR modes.
"""

if len(sys.argv) > 2:
    filename = " ".join(sys.argv[1:])
elif len(sys.argv) == 2:
    filename = sys.argv[1]
else:
    filename = input("Enter the path and filename to sign: ")

c = gpg.Context()

try:
    data, result = c.verify(open(filename))
    verified = True
except gpg.errors.BadSignatures as e:
    verified = False
    print(e)

if verified is True:
    for i in range(len(result.signatures)):
        sign = result.signatures[i]
        print("""Good signature from:
{0}
with key {1}
made at {2}
""".format(c.get_key(sign.fpr).uids[0].uid, sign.fpr,
           time.ctime(sign.timestamp)))
else:
    pass
