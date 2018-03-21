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
Takes an existing group specified as a command line parameter and converts it
to a list object 'keys' as expected by the gpg module.

Requires the groups module in this directory.
"""

if len(sys.argv) == 2:
    group = sys.argv[1]
elif len(sys.argv) == 1:
    group = input("Enter the name of the group to select keys for: ")
else:
    group = input("Enter the name of the group to select keys for: ")

keys = []
a = []

for i in range(len(group_lists)):
    a.append(group_lists[i][0])

b = a.index(group)

for i in range(len(group_lists[b][1])):
    logrus = group_lists[b][1][i]
    keys.append(gpg.Context().keylist(pattern=logrus))
