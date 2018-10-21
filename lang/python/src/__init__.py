# Copyright (C) 2016 g10 Code GmbH
# Copyright (C) 2004 Igor Belyi <belyi@users.sourceforge.net>
# Copyright (C) 2002 John Goerzen <jgoerzen@complete.org>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
"""gpg: GnuPG Interface for Python (GPGME bindings)

Welcome to gpg, the GnuPG Interface for Python.

The latest release of this package may be obtained from
https://www.gnupg.org

FEATURES
--------

 * Feature-rich, full implementation of the GPGME library.  Supports
   all GPGME features.  Callback functions may be written in pure
   Python.  Exceptions raised in callbacks are properly propagated.

 * Ability to sign, encrypt, decrypt, and verify data.

 * Ability to list keys, export and import keys, and manage the keyring.

 * Fully object-oriented with convenient classes and modules.

QUICK EXAMPLE
-------------

    >>> import gpg
    >>> with gpg.Context() as c:
    >>> with gpg.Context() as c:
    ...     cipher, _, _ = c.encrypt("Hello world :)".encode(),
    ...                              passphrase="abc")
    ...     c.decrypt(cipher, passphrase="abc")
    ...
    (b'Hello world :)',
     <gpg.results.DecryptResult object at 0x7f5ab8121080>,
     <gpg.results.VerifyResult object at 0x7f5ab81219b0>)

GENERAL OVERVIEW
----------------

For those of you familiar with GPGME, you will be right at home here.

The python gpg module is, for the most part, a direct interface to the C GPGME
library.  However, it is re-packaged in a more Pythonic way -- object-oriented
with classes and modules.  Take a look at the classes defined here -- they
correspond directly to certain object types in GPGME for C.  For instance, the
following C code:

gpgme_ctx_t context;
gpgme_new(&context);
...
gpgme_op_encrypt(context, recp, 1, plain, cipher);

Translates into the following Python code:

context = core.Context()
...
context.op_encrypt(recp, 1, plain, cipher)

The Python module automatically does error-checking and raises Python exception
gpg.errors.GPGMEError when GPGME signals an error. getcode() and getsource() of
this exception return code and source of the error.

IMPORTANT NOTE
--------------

This documentation only covers a small subset of available GPGME functions and
methods.  Please consult the documentation for the C library for comprehensive
coverage.

This library uses Python's reflection to automatically detect the methods that
are available for each class, and as such, most of those methods do not appear
explicitly anywhere. You can use dir() python built-in command on an object to
see what methods and fields it has but their meaning can often only be found in
the GPGME documentation.

HIGHER LEVEL PYTHONIC LAYER
---------------------------

A more pythonic or intuitive layer is being added above the automatically
generated lower level bindings.  This is the recommended way to access the
module as if it is ever necessary to modify the underlying GPGME API, the
higher level methods will remain the same.

The quick example above is an example of this higher layer in action, whereas
the second example demonstrating the mapping to GPGME itself is the lower
layer.  The second example in the higher layer would be more like the encrypt
line in the quick example.

FOR MORE INFORMATION
--------------------

GnuPG homepage: https://www.gnupg.org/
GPGME documentation: https://www.gnupg.org/documentation/manuals/gpgme/
GPGME Python HOWTO: http://files.au.adversary.org/crypto/gpgme-python-howto-split/index.html

To view this documentation, run help(gpg) in Python or one of the following
commands outside of Python:

        pydoc gpg
        pydoc3 gpg
        python -m pydoc gpg
        python3 -m pydoc gpg

"""

from __future__ import absolute_import, print_function, unicode_literals

from . import core
from . import errors
from . import constants
from . import util
from . import callbacks
from . import version
from .core import Context
from .core import Data

del absolute_import, print_function, unicode_literals

# Interface hygiene.

# Drop the low-level gpgme that creeps in for some reason.
gpgme = None
del gpgme

# This is a white-list of symbols.  Any other will alert pyflakes.
_ = [Context, Data, core, errors, constants, util, callbacks, version]
del _

__all__ = [
    "Context", "Data", "core", "errors", "constants", "util", "callbacks",
    "version"
]
