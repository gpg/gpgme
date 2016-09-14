#!/usr/bin/env python
#
# Copyright (C) 2016 g10 Code GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

"""Demonstrate the use of the Assuan protocol engine"""

from __future__ import absolute_import, print_function, unicode_literals
del absolute_import, print_function, unicode_literals

import pyme

with pyme.Context(protocol=pyme.constants.PROTOCOL_ASSUAN) as c:
    # Invoke the pinentry to get a confirmation.
    err = c.assuan_transact(['GET_CONFIRMATION', 'Hello there'])
    print("You chose {}.".format("cancel" if err else "ok"))
