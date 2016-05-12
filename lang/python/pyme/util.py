# $Id$
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

from . import pygpgme
from .errors import errorcheck

def process_constants(starttext, dict):
    """Called by the constant libraries to load up the appropriate constants
    from the C library."""
    index = len(starttext)
    for identifier in dir(pygpgme):
        if not identifier.startswith(starttext):
            continue
        name = identifier[index:]
        dict[name] = getattr(pygpgme, identifier)

class GpgmeWrapper(object):
    """Base class all Pyme wrappers for GPGME functionality.  Not to be
    instantiated directly."""
    def __repr__(self):
        return '<instance of %s.%s with GPG object at %s>' % \
               (__name__, self.__class__.__name__,
                self.wrapped)

    def __str__(self):
        return repr(self)

    def __hash__(self):
        return hash(repr(self.wrapped))

    def __eq__(self, other):
        if other == None:
            return False
        else:
            return repr(self.wrapped) == repr(other.wrapped)

    def _getctype(self):
        """Must be implemented by child classes.

        Must return the name of the c type."""
        raise NotImplementedError()

    def _getnameprepend(self):
        """Must be implemented by child classes.

        Must return the prefix of all c functions mapped to methods of
        this class."""
        raise NotImplementedError()

    def _errorcheck(self, name):
        """Must be implemented by child classes.

        This function must return a trueish value for all c functions
        returning gpgme_error_t."""
        raise NotImplementedError()

    def __getattr__(self, name):
        """On-the-fly function generation."""
        if name[0] == '_' or self._getnameprepend() == None:
            return None
        name = self._getnameprepend() + name
        if self._errorcheck(name):
            def _funcwrap(*args, **kwargs):
                args = [self.wrapped] + list(args)
                return errorcheck(getattr(pygpgme, name)(*args, **kwargs),
                                  "Invocation of " + name)
        else:
            def _funcwrap(*args, **kwargs):
                args = [self.wrapped] + list(args)
                return getattr(pygpgme, name)(*args, **kwargs)

        _funcwrap.__doc__ = getattr(getattr(pygpgme, name), "__doc__")
        return _funcwrap

