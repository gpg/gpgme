#!/usr/bin/env python3
# initial 20080123 build from the example:
#   very simple - probably INCOMPLETE
# 20080703 Bernhard
#   added second usage for detached signatures.
#   added output of signature.summary (another bitfield)
#   printing signature bitfield in hex format
#
# $Id$
#
# Copyright (C) 2004,2008 Igor Belyi <belyi@users.sourceforge.net>
# Copyright (c) 2008 Bernhard Reiter <bernhard@intevation.de>
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
#    along with this program. If not, see <http://www.gnu.org/licenses/>.

import sys
from pyme import core, callbacks, constants
from pyme.constants.sig import mode
from pyme.constants import protocol

def print_engine_infos():
    print("gpgme version:", core.check_version(None))
    print("engines:")

    for engine in core.get_engine_info():
        print(engine.file_name, engine.version)

    for proto in [protocol.OpenPGP, protocol.CMS]:
        print(core.get_protocol_name(proto), core.engine_check_version(proto))


def verifyprintdetails(sigfilename, filefilename=None):
    """Verify a signature, print a lot of details."""
    c = core.Context()

    # Create Data with signed text.
    sig2 = core.Data(file=sigfilename)
    if filefilename:
        file2 = core.Data(file=filefilename)
        plain2 = None
    else:
        file2 = None
        plain2 = core.Data()

    # Verify.
    c.op_verify(sig2, file2, plain2)
    result = c.op_verify_result()

    # List results for all signatures. Status equal 0 means "Ok".
    index = 0
    for sign in result.signatures:
        index += 1
        print("signature", index, ":")
        print("  summary:     %#0x" % (sign.summary))
        print("  status:      %#0x" % (sign.status))
        print("  timestamp:  ", sign.timestamp)
        print("  fingerprint:", sign.fpr)
        print("  uid:        ", c.get_key(sign.fpr, 0).uids[0].uid)

    # Print "unsigned" text if inline signature
    if plain2:
        #Rewind since verify put plain2 at EOF.
        plain2.seek(0,0)
        print("\n", plain2.read())

def main():
    print_engine_infos()

    print()

    argc= len(sys.argv)
    if argc < 2 or argc > 3:
        print("need a filename for inline signature")
        print("or two filename for detached signature and file to check")
        sys.exit(1)

    if argc == 2:
        print("trying to verify file: " + sys.argv[1])
        verifyprintdetails(sys.argv[1])
    if argc == 3:
        print("trying to verify signature %s for file %s" \
                    % (sys.argv[1], sys.argv[2]))

        verifyprintdetails(sys.argv[1], sys.argv[2])

if __name__ == "__main__":
    main()

 	  	 
