#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, unicode_literals

import gpg
import os.path
import subprocess
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

print("""
This script applies a local signature or certification to every key in a group.

Usage: local-sign-group.py <group name> [signing keyid] [gnupg homedir]
""")

c = gpg.Context(armor=True)
mkfpr = None
defkey_fpr = None
enckey_fpr = None
to_certify = []

if len(sys.argv) >= 4:
    clique = sys.argv[1]
    sigkey = sys.argv[2]
    homedir = sys.argv[3]
elif len(sys.argv) == 3:
    clique = sys.argv[1]
    sigkey = sys.argv[2]
    homedir = input("Enter the GPG configuration directory path (optional): ")
elif len(sys.argv) == 2:
    clique = sys.argv[1]
    sigkey = input("Enter the key ID to sign with (conditionally optional): ")
    homedir = input("Enter the GPG configuration directory path (optional): ")
else:
    clique = input("Enter the group matching the key(s) to locally sign: ")
    sigkey = input("Enter the key ID to sign with (conditionally optional): ")
    homedir = input("Enter the GPG configuration directory path (optional): ")

if len(homedir) == 0:
    homedir = None
elif homedir.startswith("~"):
    userdir = os.path.expanduser(homedir)
    if os.path.exists(userdir) is True:
        homedir = os.path.realpath(userdir)
    else:
        homedir = None
else:
    homedir = os.path.realpath(homedir)

if homedir is not None and os.path.exists(homedir) is False:
    homedir = None
elif homedir is not None and os.path.exists(homedir) is True:
    if os.path.isdir(homedir) is False:
        homedir = None
    else:
        pass

if homedir is not None:
    c.home_dir = homedir
else:
    pass

if len(sigkey) == 0:
    sigkey = None
else:
    pass

if sys.platform == "win32":
    gpgconfcmd = "gpgconf.exe --list-options gpg"
else:
    gpgconfcmd = "gpgconf --list-options gpg"

try:
    lines = subprocess.getoutput(gpgconfcmd).splitlines()
except:
    process = subprocess.Popen(gpgconfcmd.split(), stdout=subprocess.PIPE)
    procom = process.communicate()
    if sys.version_info[0] == 2:
        lines = procom[0].splitlines()
    else:
        lines = procom[0].decode().splitlines()

for i in range(len(lines)):
    if lines[i].startswith("default-key") is True:
        dline = lines[i]
    elif lines[i].startswith("encrypt-to") is True:
        eline = lines[i]
    else:
        pass

defkey_fpr = dline.split(":")[-1].replace('"', '').split(',')[0].upper()
enckey_fpr = eline.split(":")[-1].replace('"', '').split(',')[0].upper()

try:
    dkey = c.keylist(pattern=defkey_fpr, secret=True)
    dk = list(dkey)
except Exception as de:
    print(de)
    dk = None
    print("No valid default key.")

try:
    ekey = c.keylist(pattern=defkey_fpr, secret=True)
    ek = list(ekey)
except Exception as ee:
    print(ee)
    ek = None
    print("No valid always encrypt to key.")

if sigkey is not None:
    mykey = c.keylist(pattern=sigkey, secret=True)
    mk = list(mykey)
    mkfpr = mk[0].fpr.upper()
    c.signers = mk
else:
    if dk is None and ek is not None:
        c.signers = ek
    else:
        pass

for group in group_lists:
    if group[0] == clique:
        for logrus in group[1]:
            khole = c.keylist(pattern=logrus)
            k = list(khole)
            to_certify.append(k[0].fpr.upper())
    else:
        pass

if mkfpr is not None:
    if to_certify.count(mkfpr) > 0:
        for n in range(to_certify.count(mkfpr)):
            to_certify.remove(mkfpr)
    else:
        pass
else:
    pass

if defkey_fpr is not None:
    if to_certify.count(defkey_fpr) > 0:
        for n in range(to_certify.count(defkey_fpr)):
            to_certify.remove(defkey_fpr)
    else:
        pass
else:
    pass

if enckey_fpr is not None:
    if to_certify.count(enckey_fpr) > 0:
        for n in range(to_certify.count(enckey_fpr)):
            to_certify.remove(enckey_fpr)
    else:
        pass
else:
    pass

for fpr in to_certify:
    key = c.get_key(fpr)
    c.key_sign(key, uids=None, expires_in=False, local=True)
