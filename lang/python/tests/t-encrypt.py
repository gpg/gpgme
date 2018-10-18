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
# License along with this program; if not, see <https://www.gnu.org/licenses/>.

from __future__ import absolute_import, print_function, unicode_literals

import gpg
import support

del absolute_import, print_function, unicode_literals

c = gpg.Context()
c.set_armor(True)

source = gpg.Data("Hallo Leute\n")
sink = gpg.Data()

keys = []
keys.append(c.get_key("A0FF4590BB6122EDEF6E3C542D727CC768697734", False))
keys.append(c.get_key("D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2", False))

c.op_encrypt(keys, gpg.constants.ENCRYPT_ALWAYS_TRUST, source, sink)
result = c.op_encrypt_result()
assert not result.invalid_recipients, \
  "Invalid recipients: {}".format(", ".join(r.fpr for r in result.recipients))
support.print_data(sink)

# Idiomatic interface.
with gpg.Context(armor=True) as c:
    ciphertext, _, _ = c.encrypt(
        "Hallo Leute\n".encode(),
        recipients=keys,
        sign=False,
        always_trust=True)
    assert len(ciphertext) > 0
    assert ciphertext.find(b'BEGIN PGP MESSAGE') > 0, 'Marker not found'

    c.encrypt(
        "Hallo Leute\n".encode(),
        recipients=[c.get_key(support.encrypt_only, False)],
        sign=False,
        always_trust=True)

    try:
        c.encrypt(
            "Hallo Leute\n".encode(),
            recipients=[c.get_key(support.sign_only, False)],
            sign=False,
            always_trust=True)
    except gpg.errors.InvalidRecipients as e:
        assert len(e.recipients) == 1
        assert support.sign_only.endswith(e.recipients[0].fpr)
    else:
        assert False, "Expected an InvalidRecipients error, got none"

    try:
        # People might be tempted to provide strings.
        # We should raise something useful.
        ciphertext, _, _ = c.encrypt(
            "Hallo Leute\n", recipients=keys, sign=False, always_trust=True)
    except TypeError as e:
        # This test is a bit fragile, because the message
        # may very well change. So if the behaviour will change
        # this test can easily be deleted.
        assert "encode" in str(e)
