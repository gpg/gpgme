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

"""
Uses key IDs, fingerprints or other patterns as space separated input and
creates a keylist object for use by the gpg module.

Similar to the group-key-selection.py script, but does not require an existing
group in the gpg.conf file.
"""

if len(sys.argv) < 2:
    key_ids_str = sys.argv[1:]
elif len(sys.argv) == 2:
    key_ids_str = sys.argv[1]
elif len(sys.argv) == 1:
    key_ids_str = input("Enter the keys to select by key ID or fingerprint: ")
else:
    key_ids_str = input("Enter the keys to select by key ID or fingerprint: ")

key_ids = key_ids_str.split()
keys = []
for i in range(len(key_ids)):
    logrus = key_ids[i]
    keys.append(gpg.Context().keylist(pattern=logrus))
