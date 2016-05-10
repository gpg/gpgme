#!/usr/bin/env python3
# initial 20080124 bernhard@intevation.de
# 20080124-2: removed some superflous imports
# 20080703: adapted for pyme-0.8.0
# This script is Free Software under GNU GPL v>=2.
#
# No modification made for python3 port, Bernhard can field this one
# if it is still required.  -- Ben McGinnes
#
"""A test applicaton for gpg_get_key() protocol.CMS.

Tested on Debian Etch with
    pyme           0.8.0 (manually compiled)
    libgpgme11     1.1.6-0kk2
    gpgsm          2.0.9-0kk2
"""

import sys
from pyme import core
from pyme.constants import protocol

def printgetkeyresults(keyfpr):
    """Run gpgme_get_key()."""

    # gpgme_check_version() necessary for initialisation according to
    # gogme 1.1.6 and this is not done automatically in pyme-0.7.0
    print("gpgme version:", core.check_version(None))
    c = core.Context()
    c.set_protocol(protocol.CMS)

    key = c.get_key(keyfpr, False)

    print("got key: ", key.subkeys[0].fpr)

    for uid in key.uids:
        print(uid.uid)

def main():
    if len(sys.argv) < 2:
        print("fingerprint or unique key ID for gpgme_get_key()")
        sys.exit(1)

    printgetkeyresults(sys.argv[1])


if __name__ == "__main__":
    main()
