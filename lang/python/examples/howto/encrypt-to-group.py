#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, unicode_literals

import gpg
import sys
from groups import group_lists

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
Uses the groups module to encrypt to multiple recipients.

"""

c = gpg.Context(armor=True)

if len(sys.argv) > 3:
    group_id = sys.argv[1]
    filepath = sys.argv[2:]
elif len(sys.argv) == 3:
    group_id = sys.argv[1]
    filepath = sys.argv[2]
elif len(sys.argv) == 2:
    group_id = sys.argv[1]
    filepath = input("Enter the filename to encrypt: ")
else:
    group_id = input("Enter the group name to encrypt to: ")
    filepath = input("Enter the filename to encrypt: ")

with open(filepath, "rb") as f:
    text = f.read()

for i in range(len(group_lists)):
    if group_lists[i][0] == group_id:
        klist = group_lists[i][1]
    else:
        klist = None

logrus = []

if klist is not None:
    for i in range(len(klist)):
        apattern = list(c.keylist(pattern=klist[i], secret=False))
        if apattern[0].can_encrypt == 1:
            logrus.append(apattern[0])
        else:
            pass
    try:
        ciphertext, result, sign_result = c.encrypt(text, recipients=logrus,
                                                    add_encrypt_to=True)
    except gpg.errors.InvalidRecipients as e:
        for i in range(len(e.recipients)):
            for n in range(len(logrus)):
                if logrus[n].fpr == e.recipients[i].fpr:
                    logrus.remove(logrus[n])
                else:
                    pass
        try:
            ciphertext, result, sign_result = c.encrypt(text,
                                                        recipients=logrus,
                                                        add_encrypt_to=True,
                                                        always_trust=True)
        except:
            pass
    with open("{0}.asc".format(filepath), "wb") as f:
        f.write(ciphertext)
else:
    pass

# EOF
