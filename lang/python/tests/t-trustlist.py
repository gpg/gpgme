#!/usr/bin/env python

# Copyright (C) 2016 g10 Code GmbH
#
# This file is part of GPGME.
#
# GPGME is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# GPGME is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General
# Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, print_function, unicode_literals
del absolute_import, print_function, unicode_literals

from pyme import core, constants
import support

support.init_gpgme(constants.PROTOCOL_OpenPGP)
c = core.Context()

def dump_item(item):
    print("l={} k={} t={} o={} v={} u={}".format(
        item.level, item.keyid, item.type, item.owner_trust,
        item.validity, item.name))

c.op_trustlist_start("alice", 0)
while True:
    item = c.op_trustlist_next()
    if not item:
        break
    dump_item(item)
c.op_trustlist_end()

for item in c.op_trustlist_all("alice", 0):
    dump_item(item)
