#!/usr/bin/env python
#
# Copyright (C) 2016 g10 Code GmbH
# Copyright (C) 2004 Igor Belyi <belyi@users.sourceforge.net>
# Copyright (C) 2002 John Goerzen <jgoerzen@complete.org>
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

from __future__ import absolute_import, print_function, unicode_literals
del absolute_import, print_function, unicode_literals

import pyme

# This is the example from the GPGME manual.

parms = """<GnupgKeyParms format="internal">
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: Joe Tester
Name-Comment: with stupid passphrase
Name-Email: joe+pyme@example.org
Passphrase: Crypt0R0cks
Expire-Date: 2020-12-31
</GnupgKeyParms>
"""

with pyme.Context() as c:
    c.set_progress_cb(pyme.callbacks.progress_stdout)
    c.op_genkey(parms, None, None)
    print("Generated key with fingerprint {0}.".format(
        c.op_genkey_result().fpr))
