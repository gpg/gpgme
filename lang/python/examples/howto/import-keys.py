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
import os.path
import requests

print("""
This script imports a key or keys matching a pattern from the SKS keyserver
pool.

Uses the requests module.
""")

c = gpg.Context()

homedir = input("Enter the GPG configuration directory path (optional): ")
pattern = input("The pattern to search for in key or user IDs: ")
url = "https://sks-keyservers.net/pks/lookup"
payload = { "op": "get", "search": pattern }
hexload = { "op": "get", "search": "0x{0}".format(pattern) }

if homedir.startswith("~"):
    if os.path.exists(os.path.expanduser(homedir)) is True:
        c.home_dir = os.path.expanduser(homedir)
    else:
        pass
elif os.path.exists(homedir) is True:
    c.home_dir = homedir
else:
    pass

resp = requests.get(url, verify=True, params=payload)
if resp.ok is False:
    rhex = requests.get(url, verify=True, params=hexload)
    incoming = c.key_import(rhex.content)
else:
    incoming = c.key_import(resp.content)

summary = """
Total number of keys:   {0}
Total number imported:  {1}
Number of version 3 keys ignored:  {2}

Number of imported key objects or updates:  {3}
Number of unchanged keys:  {4}
Number of new signatures:  {5}
Number of revoked keys:    {6}
""".format(incoming.considered, len(incoming.imports),
           incoming.skipped_v3_keys, incoming.imported, incoming.unchanged,
           incoming.new_signatures, incoming.new_revocations)

print(summary)

# EOF
