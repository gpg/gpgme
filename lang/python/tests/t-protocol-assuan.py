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

import pyme

with pyme.Context(protocol=pyme.constants.PROTOCOL_ASSUAN) as c:
    # Do nothing.
    c.assuan_transact('nop')
    c.assuan_transact('NOP')
    c.assuan_transact(['NOP'])

    err = c.assuan_transact('idontexist')
    assert err.getsource() == pyme.errors.SOURCE_GPGAGENT
    assert err.getcode() == pyme.errors.ASS_UNKNOWN_CMD

    # Invoke the pinentry to get a confirmation.
    c.assuan_transact(['GET_CONFIRMATION', 'Hello there'])

    data = []
    def data_cb(line):
        data.append(line)

    err = c.assuan_transact(['GETINFO', 'version'], data_cb=data_cb)
    assert not err
    assert len(data) == 1

    data = []
    err = c.assuan_transact(['GETINFO', 's2k_count'], data_cb=data_cb)
    if not err:
        assert len(data) == 1
        assert int(data[0]) > 0

    # XXX HELP sends status lines if we could use ASSUAN_CONVEY_COMMENTS.

    status = []
    def status_cb(line, args):
        status.append((line, args))

    alphas_grip = '76F7E2B35832976B50A27A282D9B87E44577EB66'
    err = c.assuan_transact(['KEYINFO', alphas_grip], status_cb=status_cb)
    if not err:
        assert len(status) == 1
        line, args = status[0]
        assert line.startswith('KEYINFO')
        assert args.startswith(alphas_grip)

    # XXX: test these callbacks, e.g. using PRESET_PASSPHRASE
    # XXX: once issue2428 is resolved
    def inq_cb(name, args):
        print("inq_cb", name, args)
