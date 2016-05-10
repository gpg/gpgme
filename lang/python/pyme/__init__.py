# $Id$
"""
Pyme: GPGME Interface for Python
Copyright (C) 2004 Igor Belyi <belyi@users.sourceforge.net>
Copyright (C) 2002 John Goerzen <jgoerzen@complete.org>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA

Welcome to PyME, the GPGME Interface for Python.  "Pyme", when prounced,
rhymes with "Pine".

The latest release of this package may be obtained from
http://pyme.sourceforge.net
Previous releases of this package can be obtained from
http://quux.org/devel/pyme/

FEATURES
--------

 * Feature-rich, full implementation of the GPGME library.  Supports
   all GPGME features except interactive editing (coming soon).
   Callback functions may be written in pure Python.

 * Ability to sign, encrypt, decrypt, and verify data.

 * Ability to list keys, export and import keys, and manage the keyring.

 * Fully object-oriented with convenient classes and modules.

GENERAL OVERVIEW
----------------

For those of you familiar with GPGME, you will be right at home here.

Pyme is, for the most part, a direct interface to the C GPGME
library.  However, it is re-packaged in a more Pythonic way --
object-oriented with classes and modules.  Take a look at the classes
defined here -- they correspond directly to certain object types in GPGME
for C.  For instance, the following C code:

gpgme_ctx_t context;

gpgme_new(&context);

...
gpgme_op_encrypt(context, recp, 1, plain, cipher);

Translates into the following Python code:

context = core.Context()
...
context.op_encrypt(recp, 1, plain, cipher)

The Python module automatically does error-checking and raises Python
exception pyme.errors.GPGMEError when GPGME signals an error. getcode()
and getsource() of this exception return code and source of the error.

IMPORTANT NOTE
--------------
This documentation only covers a small subset of available GPGME functions and
methods.  Please consult the documentation for the C library
for comprehensive coverage.

This library uses Python's reflection to automatically detect the methods
that are available for each class, and as such, most of those methods
do not appear explicitly anywhere. You can use dir() python built-in command
on an object to see what methods and fields it has but their meaning can
be found only in GPGME documentation.

QUICK START SAMPLE PROGRAM
--------------------------
This program is not for serious encryption, but for example purposes only!

import sys
from pyme import core, constants

# Set up our input and output buffers.

plain = core.Data('This is my message.')
cipher = core.Data()

# Initialize our context.

c = core.Context()
c.set_armor(1)

# Set up the recipients.

sys.stdout.write("Enter name of your recipient: ")
name = sys.stdin.readline().strip()
c.op_keylist_start(name, 0)
r = c.op_keylist_next()

# Do the encryption.

c.op_encrypt([r], 1, plain, cipher)
cipher.seek(0,0)
print cipher.read()

Note that although there is no explicit error checking done here, the
Python GPGME library is automatically doing error-checking, and will
raise an exception if there is any problem.

This program is in the Pyme distribution as examples/simple.py.  The examples
directory contains more advanced samples as well.

FOR MORE INFORMATION
--------------------
PYME homepage: http://pyme.sourceforge.net
GPGME documentation: http://pyme.sourceforge.net/doc/gpgme/index.html
GPGME homepage: http://www.gnupg.org/gpgme.html

Base classes: pyme.core (START HERE!)
Error classes: pyme.errors
Constants: pyme.constants
Version information: pyme.version
Utilities: pyme.util

Base classes are documented at pyme.core.
Classes of pyme.util usually are not instantiated by users
directly but return by methods of base classes.

"""

__all__ = ['core', 'errors', 'constants', 'util', 'callbacks', 'version']
