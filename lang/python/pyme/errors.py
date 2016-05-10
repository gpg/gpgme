# $Id$
# Copyright (C) 2004 Igor Belyi <belyi@users.sourceforge.net>
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

class GPGMEError(Exception):
    def __init__(self, error = None, message = None):
        self.error = error
        self.message = message
    
    def getstring(self):
        message = "%s: %s" % (pygpgme.gpgme_strsource(self.error),
                              pygpgme.gpgme_strerror(self.error))
        if self.message != None:
            message = "%s: %s" % (self.message, message)
        return message

    def getcode(self):
        return pygpgme.gpgme_err_code(self.error)

    def getsource(self):
        return pygpgme.gpgme_err_source(self.error)
    
    def __str__(self):
        return "%s (%d,%d)"%(self.getstring(), self.getsource(), self.getcode())

EOF = getattr(pygpgme, "EOF")

def errorcheck(retval, extradata = None):
    if retval:
        raise GPGMEError(retval, extradata)
