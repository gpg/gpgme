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

import sys
from groups import group_lists

"""
Uses the groups module to generate Mutt crypt-hooks from gpg.conf.

"""

if len(sys.argv) >= 2:
    hook_file = sys.argv[1]
else:
    hook_file = input("Enter the filename to save the crypt-hooks in: ")

with open(hook_file, "w") as f:
    f.write("""# Change settings based upon message recipient
#
#	send-hook [!]<pattern> <command>
#
# <command> is executed when sending mail to an address matching <pattern>
#
# crypt-hook regexp key-id
#     The crypt-hook command provides a method by which you can
#     specify the ID of the public key to be used when encrypting
#     messages to a certain recipient.  The meaning of "key ID" is to
#     be taken broadly: This can be a different e-mail address, a
#     numerical key ID, or even just an arbitrary search string.  You
#     may use multiple crypt-hooks with the same regexp; multiple
#     matching crypt-hooks result in the use of multiple key-ids for a
#     recipient.
""")

for n in range(len(group_lists)):
    rule = group_lists[n][0].replace(".", "\\\\.")
    with open(hook_file, "a") as f:
        f.write("\n")
        f.write("# {0}\n".format(group_lists[n][0]))
        for i in range(len(group_lists[n][1])):
            f.write("crypt-hook {0} {1}\n".format(rule, group_lists[n][1][i]))
