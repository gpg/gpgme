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

c = gpg.Context()
seckeys = c.keylist(pattern=None, secret=True)
pubkeys = c.keylist(pattern=None, secret=False)

seclist = list(seckeys)
secnum = len(seclist)

publist = list(pubkeys)
pubnum = len(publist)

print("""
Number of secret keys:  {0}
Number of public keys:  {1}
""".format(secnum, pubnum))
