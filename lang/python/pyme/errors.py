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

from __future__ import absolute_import, print_function, unicode_literals
del absolute_import, print_function, unicode_literals

from . import gpgme
from . import util

util.process_constants('GPG_ERR_', globals())

# To appease static analysis tools, we define some constants here:
NO_ERROR = 0

class PymeError(Exception):
    pass

class GPGMEError(PymeError):
    def __init__(self, error = None, message = None):
        self.error = error
        self.message = message

    @classmethod
    def fromSyserror(cls):
        return cls(gpgme.gpgme_err_code_from_syserror())

    def getstring(self):
        message = "%s: %s" % (gpgme.gpgme_strsource(self.error),
                              gpgme.gpgme_strerror(self.error))
        if self.message != None:
            message = "%s: %s" % (self.message, message)
        return message

    def getcode(self):
        return gpgme.gpgme_err_code(self.error)

    def getsource(self):
        return gpgme.gpgme_err_source(self.error)

    def __str__(self):
        return self.getstring()

def errorcheck(retval, extradata = None):
    if retval:
        raise GPGMEError(retval, extradata)

# These errors are raised in the idiomatic interface code.

class EncryptionError(PymeError):
    pass

class InvalidRecipients(EncryptionError):
    def __init__(self, recipients):
        self.recipients = recipients
    def __str__(self):
        return ", ".join("{}: {}".format(r.fpr,
                                         gpgme.gpgme_strerror(r.reason))
                         for r in self.recipients)

class DeryptionError(PymeError):
    pass

class UnsupportedAlgorithm(DeryptionError):
    def __init__(self, algorithm):
        self.algorithm = algorithm
    def __str__(self):
        return self.algorithm

class SigningError(PymeError):
    pass

class InvalidSigners(SigningError):
    def __init__(self, signers):
        self.signers = signers
    def __str__(self):
        return ", ".join("{}: {}".format(s.fpr,
                                         gpgme.gpgme_strerror(s.reason))
                         for s in self.signers)

class VerificationError(PymeError):
    pass

class BadSignatures(VerificationError):
    def __init__(self, result):
        self.result = result
    def __str__(self):
        return ", ".join("{}: {}".format(s.fpr,
                                         gpgme.gpgme_strerror(s.status))
                         for s in self.result.signatures
                         if s.status != NO_ERROR)

class MissingSignatures(VerificationError):
    def __init__(self, result, missing):
        self.result = result
        self.missing = missing
    def __str__(self):
        return ", ".join(k.subkeys[0].fpr for k in self.missing)
