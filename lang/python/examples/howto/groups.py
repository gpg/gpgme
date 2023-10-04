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

import subprocess
import sys

"""
Intended for use with other scripts.

Usage: from groups import group_lists
"""

if sys.platform == "win32":
    gpgconfcmd = "gpgconf.exe --list-options gpg"
else:
    gpgconfcmd = "gpgconf --list-options gpg"

process = subprocess.Popen(gpgconfcmd.split(), stdout=subprocess.PIPE)
procom = process.communicate()

if sys.version_info[0] == 2:
    lines = procom[0].splitlines()
else:
    lines = procom[0].decode().splitlines()

for line in lines:
    if line.startswith("group") is True:
        break

groups = line.split(":")[-1].replace('"', '').split(',')

group_lines = []
group_lists = []

for group in groups:
    group_lines.append(group.split("="))
    group_lists.append(group.split("="))

for glist in group_lists:
    glist[1] = glist[1].split()
