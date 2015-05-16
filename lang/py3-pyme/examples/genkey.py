#!/usr/bin/env python3
# $Id$
# Copyright (C) 2004 Igor Belyi <belyi@users.sourceforge.net>
# Copyright (C) 2002 John Goerzen <jgoerzen@complete.org>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

from pyme import core, callbacks

# Initialize our context.
core.check_version(None)

c = core.Context()
c.set_armor(1)
c.set_progress_cb(callbacks.progress_stdout, None)

# This example from the GPGME manual

parms = b"""<GnupgKeyParms format="internal">
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: Joe Tester
Name-Comment: with stupid passphrase
Name-Email: joe@example.org
Passphrase: abcdabcdfs
Expire-Date: 2020-12-31
</GnupgKeyParms>
"""

c.op_genkey(parms, None, None)
print(c.op_genkey_result().fpr)
