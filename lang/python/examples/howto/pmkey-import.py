#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, unicode_literals

import gpg
import requests
import sys

del absolute_import, division, unicode_literals

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

print("""
This script searches the ProtonMail key server for the specified key and
imports it.

Usage:  pmkey-import.py [search string]
""")

c = gpg.Context(armor=True)
url = "https://api.protonmail.ch/pks/lookup"
ksearch = []

if len(sys.argv) >= 2:
    keyterm = sys.argv[1]
else:
    keyterm = input("Enter the key ID, UID or search string: ")

if keyterm.count("@") == 2 and keyterm.startswith("@") is True:
    ksearch.append(keyterm[1:])
    ksearch.append(keyterm[1:])
    ksearch.append(keyterm[1:])
elif keyterm.count("@") == 1 and keyterm.startswith("@") is True:
    ksearch.append("{0}@protonmail.com".format(keyterm[1:]))
    ksearch.append("{0}@protonmail.ch".format(keyterm[1:]))
    ksearch.append("{0}@pm.me".format(keyterm[1:]))
elif keyterm.count("@") == 0:
    ksearch.append("{0}@protonmail.com".format(keyterm))
    ksearch.append("{0}@protonmail.ch".format(keyterm))
    ksearch.append("{0}@pm.me".format(keyterm))
elif keyterm.count("@") == 2 and keyterm.startswith("@") is False:
    uidlist = keyterm.split("@")
    for uid in uidlist:
        ksearch.append("{0}@protonmail.com".format(uid))
        ksearch.append("{0}@protonmail.ch".format(uid))
        ksearch.append("{0}@pm.me".format(uid))
elif keyterm.count("@") > 2:
    uidlist = keyterm.split("@")
    for uid in uidlist:
        ksearch.append("{0}@protonmail.com".format(uid))
        ksearch.append("{0}@protonmail.ch".format(uid))
        ksearch.append("{0}@pm.me".format(uid))
else:
    ksearch.append(keyterm)

for k in ksearch:
    payload = {"op": "get", "search": k}
    try:
        r = requests.get(url, verify=True, params=payload)
        if r.ok is True:
            result = c.key_import(r.content)
        elif r.ok is False:
            result = r.content
    except Exception as e:
        result = None

    if result is not None and hasattr(result, "considered") is False:
        print("{0} for {1}".format(result.decode(), k))
    elif result is not None and hasattr(result, "considered") is True:
        num_keys = len(result.imports)
        new_revs = result.new_revocations
        new_sigs = result.new_signatures
        new_subs = result.new_sub_keys
        new_uids = result.new_user_ids
        new_scrt = result.secret_imported
        nochange = result.unchanged

        def knom():
            for ki in result.imports:
                for ku in c.get_key(ki.fpr).uids:
                    return ku.uid

        print("""
The total number of keys considered for import was:  {0}

With UIDs wholely or partially matching the following string:

        {1}

   Number of keys revoked:  {2}
 Number of new signatures:  {3}
    Number of new subkeys:  {4}
   Number of new user IDs:  {5}
Number of new secret keys:  {6}
 Number of unchanged keys:  {7}

The key IDs for all considered keys were:
""".format(num_keys, knom(), new_revs, new_sigs, new_subs, new_uids, new_scrt,
           nochange))
        for i in range(num_keys):
            print(result.imports[i].fpr)
        print("")
    elif result is None:
        print(e)
