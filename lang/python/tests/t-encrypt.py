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
from pyme import core, constants
import support

support.init_gpgme(constants.PROTOCOL_OpenPGP)
c = core.Context()
c.set_armor(True)

source = core.Data("Hallo Leute\n")
sink = core.Data()

keys = []
keys.append(c.get_key("A0FF4590BB6122EDEF6E3C542D727CC768697734", False))
keys.append(c.get_key("D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2", False))

c.op_encrypt(keys, constants.ENCRYPT_ALWAYS_TRUST, source, sink)
result = c.op_encrypt_result()
assert not result.invalid_recipients, \
  "Invalid recipients: {}".format(", ".join(r.fpr for r in result.recipients))
support.print_data(sink)

# Idiomatic interface.
with pyme.Context(armor=True) as c:
    ciphertext, _, _ = c.encrypt("Hallo Leute\n".encode(),
                                 recipients=keys,
                                 sign=False,
                                 always_trust=True)
    assert len(ciphertext) > 0
    assert ciphertext.find(b'BEGIN PGP MESSAGE') > 0, 'Marker not found'

    c.encrypt("Hallo Leute\n".encode(),
              recipients=[c.get_key(support.encrypt_only, False)],
              sign=False, always_trust=True)

    try:
        c.encrypt("Hallo Leute\n".encode(),
                  recipients=[c.get_key(support.sign_only, False)],
                  sign=False, always_trust=True)
    except pyme.errors.InvalidRecipients as e:
        assert len(e.recipients) == 1
        assert support.sign_only.endswith(e.recipients[0].fpr)
    else:
        assert False, "Expected an InvalidRecipients error, got none"
