#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, unicode_literals

# Copyright (C) 2018 Ben McGinnes <ben@gnupg.org>
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License and the GNU
# Lesser General Public Licensefor more details.
#
# You should have received a copy of the GNU General Public License and the GNU
# Lesser General Public along with this program; if not, see
# <http://www.gnu.org/licenses/>.

import os
import os.path
import sys

intro = """
This script creates a temporary directory to use as a homedir for
testing key generation tasks with the correct permissions, along
with a gpg.conf file containing the same configuration options
listed in the HOWTO.

You may wish to change the order of the cipher preferences or
remove those not relevant to your installation.  These
configuration parameters assume that all ciphers and digests are
installed and available rather than limiting to the default
ciphers and digests.

The script prompts for a directory name to be installed as a hidden
directory in the user's home directory on POSIX systems.  So if you
enter "gnupg-temp" on a Linux, BSD or OS X system, it will create
"~/.gnupg-temp" (you do not need to enter the leading dot).

This script has not been tested on Windows systems and may have
unpredictable results.  That said, it will not delete or copy over
existing data.

If the directory already exists, the script will terminate with a
message telling you to specify a new directory name.  There is no
default directory name.
"""

gpgconf = """# gpg.conf settings for key generation:
expert
allow-freeform-uid
allow-secret-key-import
trust-model tofu+pgp
tofu-default-policy unknown
enable-large-rsa
enable-dsa2
cert-digest-algo SHA512
default-preference-list TWOFISH CAMELLIA256 AES256 CAMELLIA192 AES192 CAMELLIA128 AES BLOWFISH IDEA CAST5 3DES SHA512 SHA384 SHA256 SHA224 RIPEMD160 SHA1 ZLIB BZIP2 ZIP Uncompressed
personal-cipher-preferences TWOFISH CAMELLIA256 AES256 CAMELLIA192 AES192 CAMELLIA128 AES BLOWFISH IDEA CAST5 3DES
personal-digest-preferences SHA512 SHA384 SHA256 SHA224 RIPEMD160 SHA1
personal-compress-preferences ZLIB BZIP2 ZIP Uncompressed
"""

if len(sys.argv) == 1:
    print(intro)
    new_homedir = input("Enter the temporary gnupg homedir name: ")
elif len(sys.argv) == 2:
    new_homedir = sys.argv[1]
else:
    new_homedir = " ".join(sys.argv[1:])

userdir = os.path.expanduser("~")

if new_homedir.startswith("~"):
    new_homdir.replace("~", "")
else:
    pass

if new_homedir.startswith("/"):
    new_homdir.replace("/", "")
else:
    pass

if new_homedir.startswith("."):
    new_homdir.replace(".", "_")
else:
    pass

if new_homedir.count(" ") > 0:
    new_homedir.replace(" ", "_")
else:
    pass

nh = "{0}/.{1}".format(userdir, new_homedir)

if os.path.exists(nh) is True:
    print("The {0} directory already exists.".format(nh))
else:
    print("Creating the {0} directory.".format(nh))
    os.mkdir(nh)
    os.chmod(nh, 0o700)
    with open("{0}/{1}".format(nh, "gpg.conf"), "w") as f:
        f.write(gpgconf)
    os.chmod("{0}/{1}".format(nh, "gpg.conf"), 0o600)
    print("""You may now use the {0} directory as an alternative GPG homedir:

gpg --homedir {0}
gpg --homedir --full-gen-key

Or with GPGME scripts, including the GPGME Python bindings.
""")
