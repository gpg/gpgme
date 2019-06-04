# Copyright (C) 2016-2017 g10 Code GmbH
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

from . import gpgme
from . import util

del absolute_import, print_function, unicode_literals

# To appease static analysis tools, we define some constants here.
# They are overwritten with the proper values by process_constants.
NO_ERROR = None
EOF = None

util.process_constants('GPG_ERR_', globals())
del util


class GpgError(Exception):
    """A GPG Error

    This is the base of all errors thrown by this library.

    If the error originated from GPGME, then additional information
    can be found by looking at 'code' for the error code, and 'source'
    for the errors origin.  Suitable constants for comparison are
    defined in this module.  'code_str' and 'source_str' are
    human-readable versions of the former two properties.

    If 'context' is not None, then it contains a human-readable hint
    as to where the error originated from.

    If 'results' is not None, it is a tuple containing results of the
    operation that failed.  The tuples elements are the results of the
    function that raised the error.  Some operations return results
    even though they signal an error.  Of course this information must
    be taken with a grain of salt.  But often, this information is
    useful for diagnostic uses or to give the user feedback.  Since
    the normal control flow is disrupted by the exception, the callee
    can no longer return results, hence we attach them to the
    exception objects.

    """

    def __init__(self, error=None, context=None, results=None):
        self.error = error
        self.context = context
        self.results = results

    @property
    def code(self):
        if self.error is None:
            return None
        return gpgme.gpgme_err_code(self.error)

    @property
    def code_str(self):
        if self.error is None:
            return None
        return gpgme.gpgme_strerror(self.error)

    @property
    def source(self):
        if self.error is None:
            return None
        return gpgme.gpgme_err_source(self.error)

    @property
    def source_str(self):
        if self.error is None:
            return None
        return gpgme.gpgme_strsource(self.error)

    def __str__(self):
        msgs = []
        if self.context is not None:
            msgs.append(self.context)
        if self.error is not None:
            msgs.append(self.source_str)
            msgs.append(self.code_str)
        return ': '.join(msgs)


class GPGMEError(GpgError):
    '''Generic error

    This is a generic error that wraps the underlying libraries native
    error type.  It is thrown when the low-level API is invoked and
    returns an error.  This is the error that was used in PyME.

    '''

    @classmethod
    def fromSyserror(cls):
        return cls(gpgme.gpgme_err_code_from_syserror())

    @property
    def message(self):
        return self.context

    def getstring(self):
        return str(self)

    def getcode(self):
        return self.code

    def getsource(self):
        return self.source


def errorcheck(retval, extradata=None):
    if retval:
        raise GPGMEError(retval, extradata)


class KeyNotFound(GPGMEError, KeyError):
    """Raised if a key was not found

    GPGME indicates this condition with EOF, which is not very
    idiomatic.  We raise this error that is both a GPGMEError
    indicating EOF, and a KeyError.

    """

    def __init__(self, keystr):
        self.keystr = keystr
        GPGMEError.__init__(self, EOF)

    def __str__(self):
        return self.keystr


# These errors are raised in the idiomatic interface code.


class EncryptionError(GpgError):
    pass


class InvalidRecipients(EncryptionError):
    def __init__(self, recipients, **kwargs):
        EncryptionError.__init__(self, **kwargs)
        self.recipients = recipients

    def __str__(self):
        return ", ".join("{}: {}".format(r.fpr, gpgme.gpgme_strerror(r.reason))
                         for r in self.recipients)


class DecryptionError(GpgError):
    pass


class UnsupportedAlgorithm(DecryptionError):
    def __init__(self, algorithm, **kwargs):
        DecryptionError.__init__(self, **kwargs)
        self.algorithm = algorithm

    def __str__(self):
        return self.algorithm


class SigningError(GpgError):
    pass


class InvalidSigners(SigningError):
    def __init__(self, signers, **kwargs):
        SigningError.__init__(self, **kwargs)
        self.signers = signers

    def __str__(self):
        return ", ".join("{}: {}".format(s.fpr, gpgme.gpgme_strerror(s.reason))
                         for s in self.signers)


class VerificationError(GpgError):
    def __init__(self, result, **kwargs):
        GpgError.__init__(self, **kwargs)
        self.result = result


class BadSignatures(VerificationError):
    def __str__(self):
        return ", ".join("{}: {}".format(s.fpr, gpgme.gpgme_strerror(s.status))
                         for s in self.result.signatures
                         if s.status != NO_ERROR)


class MissingSignatures(VerificationError):
    def __init__(self, result, missing, **kwargs):
        VerificationError.__init__(self, result, **kwargs)
        self.missing = missing

    def __str__(self):
        return ", ".join(k.subkeys[0].fpr for k in self.missing)
