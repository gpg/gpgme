#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, unicode_literals

import gpg
import hkp4py
import os.path
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
imports it.  Optionally enables specifying a different GnuPG home directory.

Usage:  pmkey-import-hkp.py [homedir] [search string]
   or:  pmkey-import-hkp.py [search string]
""")

c = gpg.Context(armor=True)
server = hkp4py.KeyServer("hkps://api.protonmail.ch")
keyterms = []
ksearch = []
allkeys = []
results = []
paradox = []
homeless = None

if len(sys.argv) > 3:
    homedir = sys.argv[1]
    keyterms = sys.argv[2:]
elif len(sys.argv) == 3:
    homedir = sys.argv[1]
    keyterm = sys.argv[2]
    keyterms.append(keyterm)
elif len(sys.argv) == 2:
    homedir = ""
    keyterm = sys.argv[1]
    keyterms.append(keyterm)
else:
    keyterm = input("Enter the key ID, UID or search string: ")
    homedir = input("Enter the GPG configuration directory path (optional): ")
    keyterms.append(keyterm)

if len(homedir) == 0:
    homedir = None
    homeless = False

if homedir is not None:
    if homedir.startswith("~"):
        if os.path.exists(os.path.expanduser(homedir)) is True:
            if os.path.isdir(os.path.expanduser(homedir)) is True:
                c.home_dir = os.path.realpath(os.path.expanduser(homedir))
            else:
                homeless = True
        else:
            homeless = True
    elif os.path.exists(os.path.realpath(homedir)) is True:
        if os.path.isdir(os.path.realpath(homedir)) is True:
            c.home_dir = os.path.realpath(homedir)
        else:
            homeless = True
    else:
        homeless = True

# First check to see if the homedir really is a homedir and if not, treat it as
# a search string.
if homeless is True:
    keyterms.append(homedir)
    c.home_dir = None
else:
    pass

for keyterm in keyterms:
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
    print("Checking for key for: {0}".format(k))
    import_result = None
    keys = server.search(k)
    if isinstance(keys, list) is True:
        for key in keys:
            allkeys.append(key)
            try:
                import_result = c.key_import(key.key_blob)
            except Exception as e:
                import_result = c.key_import(key.key)
    else:
        paradox.append(keys)
    results.append(import_result)

for result in results:
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
        pass
