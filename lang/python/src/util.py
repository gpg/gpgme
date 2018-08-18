# Copyright (C) 2016 g10 Code GmbH
# Copyright (C) 2004,2008 Igor Belyi <belyi@users.sourceforge.net>
# Copyright (C) 2002 John Goerzen <jgoerzen@complete.org>
#
#    This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public
#    License as published by the Free Software Foundation; either
#    version 2.1 of the License, or (at your option) any later version.
#
#    This library is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this library; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA

from __future__ import absolute_import, print_function, unicode_literals

import sys

del absolute_import, print_function, unicode_literals


def process_constants(prefix, scope):
    """Called by the constant modules to load up the constants from the C
    library starting with PREFIX.  Matching constants will be inserted
    into SCOPE with PREFIX stripped from the names.  Returns the names
    of inserted constants.

    """
    from . import gpgme
    index = len(prefix)
    constants = {
        identifier[index:]: getattr(gpgme, identifier)
        for identifier in dir(gpgme) if identifier.startswith(prefix)
    }
    scope.update(constants)
    return list(constants.keys())


def percent_escape(s):
    return ''.join('%{0:2x}'.format(ord(c))
                   if c == '+' or c == '"' or c == '%' or ord(c) <= 0x20 else c
                   for c in s)


# Python2/3 compatibility
if sys.version_info[0] == 3:
    # Python3
    def is_a_string(x):
        return isinstance(x, str)
else:
    # Python2
    def is_a_string(x):
        return isinstance(x, basestring)
