#!/usr/bin/env python
#
# Copyright (C) 2016 g10 Code GmbH
# Copyright (C) 2004,2008 Igor Belyi <belyi@users.sourceforge.net>
# Copyright (c) 2008 Bernhard Reiter <bernhard@intevation.de>
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

import sys
from pyme import core
from pyme.constants import protocol

def print_engine_infos():
    print("gpgme version:", core.check_version(None))
    print("engines:")

    for engine in core.get_engine_info():
        print(engine.file_name, engine.version)

    for proto in [protocol.OpenPGP, protocol.CMS]:
        print("Have {}? {}".format(core.get_protocol_name(proto),
                                   core.engine_check_version(proto)))


def verifyprintdetails(filename, detached_sig_filename=None):
    """Verify a signature, print a lot of details."""
    with core.Context() as c:

        # Verify.
        data, result = c.verify(open(filename),
                                open(detached_sig_filename)
                                if detached_sig_filename else None)

        # List results for all signatures. Status equal 0 means "Ok".
        for index, sign in enumerate(result.signatures):
            print("signature", index, ":")
            print("  summary:     %#0x" % (sign.summary))
            print("  status:      %#0x" % (sign.status))
            print("  timestamp:  ", sign.timestamp)
            print("  fingerprint:", sign.fpr)
            print("  uid:        ", c.get_key(sign.fpr, 0).uids[0].uid)

    # Print "unsigned" text if inline signature
    if data:
        sys.stdout.buffer.write(data)

def main():
    print_engine_infos()
    print()

    argc = len(sys.argv)
    if argc < 2 or argc > 3:
        sys.exit(
            "Usage: {} <filename>[ <detached_signature_filename>]".format(
                sys.argv[0]))

    if argc == 2:
        print("trying to verify file {}.".format(sys.argv[1]))
        verifyprintdetails(sys.argv[1])
    if argc == 3:
        print("trying to verify signature {1} for file {0}.".format(*sys.argv))
        verifyprintdetails(sys.argv[1], sys.argv[2])

if __name__ == "__main__":
    main()
