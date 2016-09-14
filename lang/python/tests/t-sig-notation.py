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

import os
from pyme import core, constants
import support

expected_notations = {
    "laughing@me": ("Just Squeeze Me", constants.SIG_NOTATION_HUMAN_READABLE),
    "preferred-email-encoding@pgp.com": ("pgpmime",
                                         constants.SIG_NOTATION_HUMAN_READABLE
                                         | constants.SIG_NOTATION_CRITICAL),
    None: ("http://www.gnu.org/policy/", 0),
}

# GnuPG prior to 2.1.13 did not report the critical flag correctly.
with core.Context() as c:
    version = c.engine_info.version
    have_correct_sig_data = not (version.startswith("1.")
                                 or version == "2.1.1"
                                 or (version.startswith("2.1.1")
                                     and version[5] < '3'))

def check_result(result):
    assert len(result.signatures) == 1, "Unexpected number of signatures"
    sig = result.signatures[0]
    assert len(sig.notations) == len(expected_notations)

    for r in sig.notations:
        assert not 'name_len' in dir(r)
        assert not 'value_len' in dir(r)
        assert r.name in expected_notations
        value, flags = expected_notations.pop(r.name)

        assert r.value == value, \
            "Expected {!r}, got {!r}".format(value, r.value)
        assert r.human_readable \
            == bool(flags&constants.SIG_NOTATION_HUMAN_READABLE)
        assert r.critical \
            == (bool(flags&constants.SIG_NOTATION_CRITICAL)
                if have_correct_sig_data else False)

    assert len(expected_notations) == 0

support.init_gpgme(constants.PROTOCOL_OpenPGP)

source = core.Data("Hallo Leute\n")
signed = core.Data()

c = core.Context()
for name, (value, flags) in expected_notations.items():
    c.sig_notation_add(name, value, flags)

c.op_sign(source, signed, constants.SIG_MODE_NORMAL)

signed.seek(0, os.SEEK_SET)
sink = core.Data()
c.op_verify(signed, None, sink)
result = c.op_verify_result()
check_result(result)
