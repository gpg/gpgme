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

"""Core functionality

Core functionality of GPGME wrapped in a object-oriented fashion.
Provides the 'Context' class for performing cryptographic operations,
and the 'Data' class describing buffers of data.

"""

from __future__ import absolute_import, print_function, unicode_literals
del absolute_import, print_function, unicode_literals

import re
import os
import warnings
import weakref
from . import gpgme
from .errors import errorcheck, GPGMEError
from . import constants
from . import errors
from . import util

class GpgmeWrapper(object):
    """Base wrapper class

    Not to be instantiated directly.

    """

    def __init__(self, wrapped):
        self._callback_excinfo = None
        self.wrapped = wrapped

    def __repr__(self):
        return '<{}/{!r}>'.format(super(GpgmeWrapper, self).__repr__(),
                                  self.wrapped)

    def __str__(self):
        acc = ['{}.{}'.format(__name__, self.__class__.__name__)]
        flags = [f for f in self._boolean_properties if getattr(self, f)]
        if flags:
            acc.append('({})'.format(' '.join(flags)))

        return '<{}>'.format(' '.join(acc))

    def __hash__(self):
        return hash(repr(self.wrapped))

    def __eq__(self, other):
        if other == None:
            return False
        else:
            return repr(self.wrapped) == repr(other.wrapped)

    @property
    def _ctype(self):
        """The name of the c type wrapped by this class

        Must be set by child classes.

        """
        raise NotImplementedError()

    @property
    def _cprefix(self):
        """The common prefix of c functions wrapped by this class

        Must be set by child classes.

        """
        raise NotImplementedError()

    def _errorcheck(self, name):
        """Must be implemented by child classes.

        This function must return a trueish value for all c functions
        returning gpgme_error_t."""
        raise NotImplementedError()

    """The set of all boolean properties"""
    _boolean_properties = set()

    def __wrap_boolean_property(self, key, do_set=False, value=None):
        get_func = getattr(gpgme,
                           "{}get_{}".format(self._cprefix, key))
        set_func = getattr(gpgme,
                           "{}set_{}".format(self._cprefix, key))
        def get(slf):
            return bool(get_func(slf.wrapped))
        def set_(slf, value):
            set_func(slf.wrapped, bool(value))

        p = property(get, set_, doc="{} flag".format(key))
        setattr(self.__class__, key, p)

        if do_set:
            set_(self, bool(value))
        else:
            return get(self)

    _munge_docstring = re.compile(r'gpgme_([^(]*)\(([^,]*), (.*\) -> .*)')
    def __getattr__(self, key):
        """On-the-fly generation of wrapper methods and properties"""
        if key[0] == '_' or self._cprefix == None:
            return None

        if key in self._boolean_properties:
            return self.__wrap_boolean_property(key)

        name = self._cprefix + key
        func = getattr(gpgme, name)

        if self._errorcheck(name):
            def _funcwrap(slf, *args):
                result = func(slf.wrapped, *args)
                if slf._callback_excinfo:
                    gpgme.pyme_raise_callback_exception(slf)
                return errorcheck(result, "Invocation of " + name)
        else:
            def _funcwrap(slf, *args):
                result = func(slf.wrapped, *args)
                if slf._callback_excinfo:
                    gpgme.pyme_raise_callback_exception(slf)
                return result

        doc = self._munge_docstring.sub(r'\2.\1(\3', getattr(func, "__doc__"))
        _funcwrap.__doc__ = doc

        # Monkey-patch the class.
        setattr(self.__class__, key, _funcwrap)

        # Bind the method to 'self'.
        def wrapper(*args):
            return _funcwrap(self, *args)
        wrapper.__doc__ = doc

        return wrapper

    def __setattr__(self, key, value):
        """On-the-fly generation of properties"""
        if key in self._boolean_properties:
            self.__wrap_boolean_property(key, True, value)
        else:
            super(GpgmeWrapper, self).__setattr__(key, value)

class Context(GpgmeWrapper):
    """Context for cryptographic operations

    All cryptographic operations in GPGME are performed within a
    context, which contains the internal state of the operation as
    well as configuration parameters.  By using several contexts you
    can run several cryptographic operations in parallel, with
    different configuration.

    Access to a context must be synchronized.

    """

    def __init__(self, armor=False, textmode=False, offline=False,
                 signers=[], pinentry_mode=constants.PINENTRY_MODE_DEFAULT,
                 protocol=constants.PROTOCOL_OpenPGP,
                 wrapped=None):
        """Construct a context object

        Keyword arguments:
        armor		-- enable ASCII armoring (default False)
        textmode	-- enable canonical text mode (default False)
        offline		-- do not contact external key sources (default False)
        signers		-- list of keys used for signing (default [])
        pinentry_mode	-- pinentry mode (default PINENTRY_MODE_DEFAULT)
        protocol	-- protocol to use (default PROTOCOL_OpenPGP)

        """
        if wrapped:
            self.own = False
        else:
            tmp = gpgme.new_gpgme_ctx_t_p()
            errorcheck(gpgme.gpgme_new(tmp))
            wrapped = gpgme.gpgme_ctx_t_p_value(tmp)
            gpgme.delete_gpgme_ctx_t_p(tmp)
            self.own = True
        super(Context, self).__init__(wrapped)
        self.armor = armor
        self.textmode = textmode
        self.offline = offline
        self.signers = signers
        self.pinentry_mode = pinentry_mode
        self.protocol = protocol

    def encrypt(self, plaintext, recipients=[], sign=True, sink=None,
                passphrase=None, always_trust=False, add_encrypt_to=False,
                prepare=False, expect_sign=False, compress=True):
        """Encrypt data

        Encrypt the given plaintext for the given recipients.  If the
        list of recipients is empty, the data is encrypted
        symmetrically with a passphrase.

        The passphrase can be given as parameter, using a callback
        registered at the context, or out-of-band via pinentry.

        Keyword arguments:
        recipients	-- list of keys to encrypt to
        sign		-- sign plaintext (default True)
        sink		-- write result to sink instead of returning it
        passphrase	-- for symmetric encryption
        always_trust	-- always trust the keys (default False)
        add_encrypt_to	-- encrypt to configured additional keys (default False)
        prepare		-- (ui) prepare for encryption (default False)
        expect_sign	-- (ui) prepare for signing (default False)
        compress	-- compress plaintext (default True)

        Returns:
        ciphertext	-- the encrypted data (or None if sink is given)
        result		-- additional information about the encryption
        sign_result	-- additional information about the signature(s)

        Raises:
        InvalidRecipients -- if encryption using a particular key failed
        InvalidSigners	-- if signing using a particular key failed
        GPGMEError	-- as signaled by the underlying library

        """
        ciphertext = sink if sink else Data()
        flags = 0
        flags |= always_trust * constants.ENCRYPT_ALWAYS_TRUST
        flags |= (not add_encrypt_to) * constants.ENCRYPT_NO_ENCRYPT_TO
        flags |= prepare * constants.ENCRYPT_PREPARE
        flags |= expect_sign * constants.ENCRYPT_EXPECT_SIGN
        flags |= (not compress) * constants.ENCRYPT_NO_COMPRESS

        if passphrase != None:
            old_pinentry_mode = self.pinentry_mode
            old_passphrase_cb = getattr(self, '_passphrase_cb', None)
            self.pinentry_mode = constants.PINENTRY_MODE_LOOPBACK
            def passphrase_cb(hint, desc, prev_bad, hook=None):
                return passphrase
            self.set_passphrase_cb(passphrase_cb)

        try:
            if sign:
                self.op_encrypt_sign(recipients, flags, plaintext, ciphertext)
            else:
                self.op_encrypt(recipients, flags, plaintext, ciphertext)
        except errors.GPGMEError as e:
            if e.getcode() == errors.UNUSABLE_PUBKEY:
                result = self.op_encrypt_result()
                if result.invalid_recipients:
                    raise errors.InvalidRecipients(result.invalid_recipients)
            if e.getcode() == errors.UNUSABLE_SECKEY:
                sig_result = self.op_sign_result()
                if sig_result.invalid_signers:
                    raise errors.InvalidSigners(sig_result.invalid_signers)
            raise
        finally:
            if passphrase != None:
                self.pinentry_mode = old_pinentry_mode
                if old_passphrase_cb:
                    self.set_passphrase_cb(*old_passphrase_cb[1:])

        result = self.op_encrypt_result()
        assert not result.invalid_recipients
        sig_result = self.op_sign_result() if sign else None
        assert not sig_result or not sig_result.invalid_signers

        cipherbytes = None
        if not sink:
            ciphertext.seek(0, os.SEEK_SET)
            cipherbytes = ciphertext.read()
        return cipherbytes, result, sig_result

    def decrypt(self, ciphertext, sink=None, passphrase=None, verify=True):
        """Decrypt data

        Decrypt the given ciphertext and verify any signatures.  If
        VERIFY is an iterable of keys, the ciphertext must be signed
        by all those keys, otherwise an error is raised.

        If the ciphertext is symmetrically encrypted using a
        passphrase, that passphrase can be given as parameter, using a
        callback registered at the context, or out-of-band via
        pinentry.

        Keyword arguments:
        sink		-- write result to sink instead of returning it
        passphrase	-- for symmetric decryption
        verify		-- check signatures (default True)

        Returns:
        plaintext	-- the decrypted data (or None if sink is given)
        result		-- additional information about the decryption
        verify_result	-- additional information about the signature(s)

        Raises:
        UnsupportedAlgorithm -- if an unsupported algorithm was used
        BadSignatures	-- if a bad signature is encountered
        MissingSignatures -- if expected signatures are missing or bad
        GPGMEError	-- as signaled by the underlying library

        """
        plaintext = sink if sink else Data()

        if passphrase != None:
            old_pinentry_mode = self.pinentry_mode
            old_passphrase_cb = getattr(self, '_passphrase_cb', None)
            self.pinentry_mode = constants.PINENTRY_MODE_LOOPBACK
            def passphrase_cb(hint, desc, prev_bad, hook=None):
                return passphrase
            self.set_passphrase_cb(passphrase_cb)

        try:
            if verify:
                self.op_decrypt_verify(ciphertext, plaintext)
            else:
                self.op_decrypt(ciphertext, plaintext)
        finally:
            if passphrase != None:
                self.pinentry_mode = old_pinentry_mode
                if old_passphrase_cb:
                    self.set_passphrase_cb(*old_passphrase_cb[1:])

        result = self.op_decrypt_result()
        verify_result = self.op_verify_result() if verify else None
        if result.unsupported_algorithm:
            raise errors.UnsupportedAlgorithm(result.unsupported_algorithm)

        if verify:
            if any(s.status != errors.NO_ERROR
                   for s in verify_result.signatures):
                raise errors.BadSignatures(verify_result)

        if verify and verify != True:
            missing = list()
            for key in verify:
                ok = False
                for subkey in key.subkeys:
                    for sig in verify_result.signatures:
                        if sig.summary & constants.SIGSUM_VALID == 0:
                            continue
                        if subkey.can_sign and subkey.fpr == sig.fpr:
                            ok = True
                            break
                    if ok:
                        break
                if not ok:
                    missing.append(key)
            if missing:
                raise errors.MissingSignatures(verify_result, missing)

        plainbytes = None
        if not sink:
            plaintext.seek(0, os.SEEK_SET)
            plainbytes = plaintext.read()
        return plainbytes, result, verify_result

    def sign(self, data, sink=None, mode=constants.SIG_MODE_NORMAL):
        """Sign data

        Sign the given data with either the configured default local
        key, or the 'signers' keys of this context.

        Keyword arguments:
        mode		-- signature mode (default: normal, see below)
        sink		-- write result to sink instead of returning it

        Returns:
        either
          signed_data	-- encoded data and signature (normal mode)
          signature	-- only the signature data (detached mode)
          cleartext	-- data and signature as text (cleartext mode)
            (or None if sink is given)
        result		-- additional information about the signature(s)

        Raises:
        InvalidSigners	-- if signing using a particular key failed
        GPGMEError	-- as signaled by the underlying library

        """
        signeddata = sink if sink else Data()

        try:
            self.op_sign(data, signeddata, mode)
        except errors.GPGMEError as e:
            if e.getcode() == errors.UNUSABLE_SECKEY:
                result = self.op_sign_result()
                if result.invalid_signers:
                    raise errors.InvalidSigners(result.invalid_signers)
            raise

        result = self.op_sign_result()
        assert not result.invalid_signers

        signedbytes = None
        if not sink:
            signeddata.seek(0, os.SEEK_SET)
            signedbytes = signeddata.read()
        return signedbytes, result

    def verify(self, signed_data, signature=None, sink=None, verify=[]):
        """Verify signatures

        Verify signatures over data.  If VERIFY is an iterable of
        keys, the ciphertext must be signed by all those keys,
        otherwise an error is raised.

        Keyword arguments:
        signature	-- detached signature data
        sink		-- write result to sink instead of returning it

        Returns:
        data		-- the plain data
            (or None if sink is given, or we verified a detached signature)
        result		-- additional information about the signature(s)

        Raises:
        BadSignatures	-- if a bad signature is encountered
        MissingSignatures -- if expected signatures are missing or bad
        GPGMEError	-- as signaled by the underlying library

        """
        if signature:
            # Detached signature, we don't return the plain text.
            data = None
        else:
            data = sink if sink else Data()

        if signature:
            self.op_verify(signature, signed_data, None)
        else:
            self.op_verify(signed_data, None, data)

        result = self.op_verify_result()
        if any(s.status != errors.NO_ERROR for s in result.signatures):
            raise errors.BadSignatures(result)

        missing = list()
        for key in verify:
            ok = False
            for subkey in key.subkeys:
                for sig in result.signatures:
                    if sig.summary & constants.SIGSUM_VALID == 0:
                        continue
                    if subkey.can_sign and subkey.fpr == sig.fpr:
                        ok = True
                        break
                if ok:
                    break
            if not ok:
                missing.append(key)
        if missing:
            raise errors.MissingSignatures(result, missing)

        plainbytes = None
        if data and not sink:
            data.seek(0, os.SEEK_SET)
            plainbytes = data.read()
        return plainbytes, result

    def keylist(self, pattern=None, secret=False):
        """List keys

        Keyword arguments:
        pattern	-- return keys matching pattern (default: all keys)
        secret	-- return only secret keys

        Returns:
                -- an iterator returning key objects

        Raises:
        GPGMEError	-- as signaled by the underlying library
        """
        return self.op_keylist_all(pattern, secret)

    def assuan_transact(self, command,
                        data_cb=None, inquire_cb=None, status_cb=None):
        """Issue a raw assuan command

        This function can be used to issue a raw assuan command to the
        engine.

        If command is a string or bytes, it will be used as-is.  If it
        is an iterable of strings, it will be properly escaped and
        joined into an well-formed assuan command.

        Keyword arguments:
        data_cb		-- a callback receiving data lines
        inquire_cb	-- a callback providing more information
        status_cb	-- a callback receiving status lines

        Returns:
        result		-- the result of command as GPGMEError

        Raises:
        GPGMEError	-- as signaled by the underlying library

        """

        if isinstance(command, (str, bytes)):
            cmd = command
        else:
            cmd = " ".join(util.percent_escape(f) for f in command)

        errptr = gpgme.new_gpgme_error_t_p()

        err = gpgme.gpgme_op_assuan_transact_ext(
            self.wrapped,
            cmd,
            (weakref.ref(self), data_cb) if data_cb else None,
            (weakref.ref(self), inquire_cb) if inquire_cb else None,
            (weakref.ref(self), status_cb) if status_cb else None,
            errptr)

        if self._callback_excinfo:
            gpgme.pyme_raise_callback_exception(self)

        errorcheck(err)

        status = gpgme.gpgme_error_t_p_value(errptr)
        gpgme.delete_gpgme_error_t_p(errptr)

        return GPGMEError(status) if status != 0 else None

    def interact(self, key, func, sink=None, flags=0, fnc_value=None):
        """Interact with the engine

        This method can be used to edit keys and cards interactively.
        KEY is the key to edit, FUNC is called repeatedly with two
        unicode arguments, 'keyword' and 'args'.  See the GPGME manual
        for details.

        Keyword arguments:
        sink		-- if given, additional output is written here
        flags		-- use constants.INTERACT_CARD to edit a card

        Raises:
        GPGMEError	-- as signaled by the underlying library

        """
        if key == None:
            raise ValueError("First argument cannot be None")

        if sink == None:
            sink = Data()

        if fnc_value:
            opaquedata = (weakref.ref(self), func, fnc_value)
        else:
            opaquedata = (weakref.ref(self), func)

        result = gpgme.gpgme_op_interact(self.wrapped, key, flags,
                                         opaquedata, sink)
        if self._callback_excinfo:
            gpgme.pyme_raise_callback_exception(self)
        errorcheck(result)

    @property
    def signers(self):
        """Keys used for signing"""
        return [self.signers_enum(i) for i in range(self.signers_count())]
    @signers.setter
    def signers(self, signers):
        old = self.signers
        self.signers_clear()
        try:
            for key in signers:
                self.signers_add(key)
        except:
            self.signers = old
            raise

    @property
    def pinentry_mode(self):
        """Pinentry mode"""
        return self.get_pinentry_mode()
    @pinentry_mode.setter
    def pinentry_mode(self, value):
        self.set_pinentry_mode(value)

    @property
    def protocol(self):
        """Protocol to use"""
        return self.get_protocol()
    @protocol.setter
    def protocol(self, value):
        errorcheck(gpgme.gpgme_engine_check_version(value))
        self.set_protocol(value)

    _ctype = 'gpgme_ctx_t'
    _cprefix = 'gpgme_'

    def _errorcheck(self, name):
        """This function should list all functions returning gpgme_error_t"""
        return ((name.startswith('gpgme_op_')
                 and not name.endswith('_result'))
                or name in {
                    'gpgme_set_ctx_flag',
                    'gpgme_set_protocol',
                    'gpgme_set_sub_protocol',
                    'gpgme_set_keylist_mode',
                    'gpgme_set_pinentry_mode',
                    'gpgme_set_locale',
                    'gpgme_set_engine_info',
                    'gpgme_signers_add',
                    'gpgme_get_sig_key',
                    'gpgme_sig_notation_add',
                    'gpgme_cancel',
                    'gpgme_cancel_async',
                    'gpgme_cancel_get_key',
                })

    _boolean_properties = {'armor', 'textmode', 'offline'}

    def __del__(self):
        if not gpgme:
            # At interpreter shutdown, gpgme is set to NONE.
            return

        self._free_passcb()
        self._free_progresscb()
        self._free_statuscb()
        if self.own and self.wrapped and gpgme.gpgme_release:
            gpgme.gpgme_release(self.wrapped)
            self.wrapped = None

    # Implement the context manager protocol.
    def __enter__(self):
        return self
    def __exit__(self, type, value, tb):
        self.__del__()

    def op_keylist_all(self, *args, **kwargs):
        self.op_keylist_start(*args, **kwargs)
        key = self.op_keylist_next()
        while key:
            yield key
            key = self.op_keylist_next()
        self.op_keylist_end()

    def op_keylist_next(self):
        """Returns the next key in the list created
        by a call to op_keylist_start().  The object returned
        is of type Key."""
        ptr = gpgme.new_gpgme_key_t_p()
        try:
            errorcheck(gpgme.gpgme_op_keylist_next(self.wrapped, ptr))
            key = gpgme.gpgme_key_t_p_value(ptr)
        except errors.GPGMEError as excp:
            key = None
            if excp.getcode() != errors.EOF:
                raise excp
        gpgme.delete_gpgme_key_t_p(ptr)
        if key:
            key.__del__ = lambda self: gpgme.gpgme_key_unref(self)
            return key

    def get_key(self, fpr, secret):
        """Return the key corresponding to the fingerprint 'fpr'"""
        ptr = gpgme.new_gpgme_key_t_p()
        errorcheck(gpgme.gpgme_get_key(self.wrapped, fpr, ptr, secret))
        key = gpgme.gpgme_key_t_p_value(ptr)
        gpgme.delete_gpgme_key_t_p(ptr)
        if key:
            key.__del__ = lambda self: gpgme.gpgme_key_unref(self)
            return key

    def op_trustlist_all(self, *args, **kwargs):
        self.op_trustlist_start(*args, **kwargs)
        trust = self.op_trustlist_next()
        while trust:
            yield trust
            trust = self.op_trustlist_next()
        self.op_trustlist_end()

    def op_trustlist_next(self):
        """Returns the next trust item in the list created
        by a call to op_trustlist_start().  The object returned
        is of type TrustItem."""
        ptr = gpgme.new_gpgme_trust_item_t_p()
        try:
            errorcheck(gpgme.gpgme_op_trustlist_next(self.wrapped, ptr))
            trust = gpgme.gpgme_trust_item_t_p_value(ptr)
        except errors.GPGMEError as excp:
            trust = None
            if excp.getcode() != errors.EOF:
                raise
        gpgme.delete_gpgme_trust_item_t_p(ptr)
        return trust

    def set_passphrase_cb(self, func, hook=None):
        """Sets the passphrase callback to the function specified by func.

        When the system needs a passphrase, it will call func with three args:
        hint, a string describing the key it needs the passphrase for;
        desc, a string describing the passphrase it needs;
        prev_bad, a boolean equal True if this is a call made after
        unsuccessful previous attempt.

        If hook has a value other than None it will be passed into the func
        as a forth argument.

        Please see the GPGME manual for more information.
        """
        if func == None:
            hookdata = None
        else:
            if hook == None:
                hookdata = (weakref.ref(self), func)
            else:
                hookdata = (weakref.ref(self), func, hook)
        gpgme.pyme_set_passphrase_cb(self, hookdata)

    def _free_passcb(self):
        if gpgme.pyme_set_passphrase_cb:
            self.set_passphrase_cb(None)

    def set_progress_cb(self, func, hook=None):
        """Sets the progress meter callback to the function specified by FUNC.
        If FUNC is None, the callback will be cleared.

        This function will be called to provide an interactive update
        of the system's progress.  The function will be called with
        three arguments, type, total, and current.  If HOOK is not
        None, it will be supplied as fourth argument.

        Please see the GPGME manual for more information.

        """
        if func == None:
            hookdata = None
        else:
            if hook == None:
                hookdata = (weakref.ref(self), func)
            else:
                hookdata = (weakref.ref(self), func, hook)
        gpgme.pyme_set_progress_cb(self, hookdata)

    def _free_progresscb(self):
        if gpgme.pyme_set_progress_cb:
            self.set_progress_cb(None)

    def set_status_cb(self, func, hook=None):
        """Sets the status callback to the function specified by FUNC.  If
        FUNC is None, the callback will be cleared.

        The function will be called with two arguments, keyword and
        args.  If HOOK is not None, it will be supplied as third
        argument.

        Please see the GPGME manual for more information.

        """
        if func == None:
            hookdata = None
        else:
            if hook == None:
                hookdata = (weakref.ref(self), func)
            else:
                hookdata = (weakref.ref(self), func, hook)
        gpgme.pyme_set_status_cb(self, hookdata)

    def _free_statuscb(self):
        if gpgme.pyme_set_status_cb:
            self.set_status_cb(None)

    @property
    def engine_info(self):
        """Configuration of the engine currently in use"""
        p = self.protocol
        infos = [i for i in self.get_engine_info() if i.protocol == p]
        assert len(infos) == 1
        return infos[0]

    def get_engine_info(self):
        """Get engine configuration

        Returns information about all configured and installed
        engines.

        Returns:
        infos		-- a list of engine infos

        """
        return gpgme.gpgme_ctx_get_engine_info(self.wrapped)

    def set_engine_info(self, proto, file_name=None, home_dir=None):
        """Change engine configuration

        Changes the configuration of the crypto engine implementing
        the protocol 'proto' for the context.

        Keyword arguments:
        file_name	-- engine program file name (unchanged if None)
        home_dir	-- configuration directory (unchanged if None)

        """
        errorcheck(gpgme.gpgme_ctx_set_engine_info(
            self.wrapped, proto, file_name, home_dir))

    def wait(self, hang):
        """Wait for asynchronous call to finish. Wait forever if hang is True.
        Raises an exception on errors.

        Please read the GPGME manual for more information.

        """
        ptr = gpgme.new_gpgme_error_t_p()
        gpgme.gpgme_wait(self.wrapped, ptr, hang)
        status = gpgme.gpgme_error_t_p_value(ptr)
        gpgme.delete_gpgme_error_t_p(ptr)
        errorcheck(status)

    def op_edit(self, key, func, fnc_value, out):
        """Start key editing using supplied callback function

        Note: This interface is deprecated and will be removed with
        GPGME 1.8.  Please use .interact instead.  Furthermore, we
        implement this using gpgme_op_interact, so callbacks will get
        called with string keywords instead of numeric status
        messages.  Code that is using constants.STATUS_X or
        constants.status.X will continue to work, whereas code using
        magic numbers will break as a result.

        """
        warnings.warn("Call to deprecated method op_edit.",
                      category=DeprecationWarning)
        return self.interact(key, func, sink=out, fnc_value=fnc_value)


class Data(GpgmeWrapper):
    """Data buffer

    A lot of data has to be exchanged between the user and the crypto
    engine, like plaintext messages, ciphertext, signatures and
    information about the keys.  The technical details about
    exchanging the data information are completely abstracted by
    GPGME.  The user provides and receives the data via `gpgme_data_t'
    objects, regardless of the communication protocol between GPGME
    and the crypto engine in use.

    This Data class is the implementation of the GpgmeData objects.

    Please see the information about __init__ for instantiation.

    """

    _ctype = 'gpgme_data_t'
    _cprefix = 'gpgme_data_'

    def _errorcheck(self, name):
        """This function should list all functions returning gpgme_error_t"""
        return name not in {
            'gpgme_data_release_and_get_mem',
            'gpgme_data_get_encoding',
            'gpgme_data_seek',
            'gpgme_data_get_file_name',
        }

    def __init__(self, string=None, file=None, offset=None,
                 length=None, cbs=None, copy=True):
        """Initialize a new gpgme_data_t object.

        If no args are specified, make it an empty object.

        If string alone is specified, initialize it with the data
        contained there.

        If file, offset, and length are all specified, file must
        be either a filename or a file-like object, and the object
        will be initialized by reading the specified chunk from the file.

        If cbs is specified, it MUST be a tuple of the form:

        (read_cb, write_cb, seek_cb, release_cb[, hook])

        where the first four items are functions implementing reading,
        writing, seeking the data, and releasing any resources once
        the data object is deallocated.  The functions must match the
        following prototypes:

            def read(amount, hook=None):
                return <a b"bytes" object>

            def write(data, hook=None):
                return <the number of bytes written>

            def seek(offset, whence, hook=None):
                return <the new file position>

            def release(hook=None):
                <return value and exceptions are ignored>

        The functions may be bound methods.  In that case, you can
        simply use the 'self' reference instead of using a hook.

        If file is specified without any other arguments, then
        it must be a filename, and the object will be initialized from
        that file.

        """
        super(Data, self).__init__(None)
        self.data_cbs = None

        if cbs != None:
            self.new_from_cbs(*cbs)
        elif string != None:
            self.new_from_mem(string, copy)
        elif file != None and offset != None and length != None:
            self.new_from_filepart(file, offset, length)
        elif file != None:
            if util.is_a_string(file):
                self.new_from_file(file, copy)
            else:
                self.new_from_fd(file)
        else:
            self.new()

    def __del__(self):
        if not gpgme:
            # At interpreter shutdown, gpgme is set to NONE.
            return

        if self.wrapped != None and gpgme.gpgme_data_release:
            gpgme.gpgme_data_release(self.wrapped)
            if self._callback_excinfo:
                gpgme.pyme_raise_callback_exception(self)
            self.wrapped = None
        self._free_datacbs()

    # Implement the context manager protocol.
    def __enter__(self):
        return self
    def __exit__(self, type, value, tb):
        self.__del__()

    def _free_datacbs(self):
        self._data_cbs = None

    def new(self):
        tmp = gpgme.new_gpgme_data_t_p()
        errorcheck(gpgme.gpgme_data_new(tmp))
        self.wrapped = gpgme.gpgme_data_t_p_value(tmp)
        gpgme.delete_gpgme_data_t_p(tmp)

    def new_from_mem(self, string, copy=True):
        tmp = gpgme.new_gpgme_data_t_p()
        errorcheck(gpgme.gpgme_data_new_from_mem(tmp,string,len(string),copy))
        self.wrapped = gpgme.gpgme_data_t_p_value(tmp)
        gpgme.delete_gpgme_data_t_p(tmp)

    def new_from_file(self, filename, copy=True):
        tmp = gpgme.new_gpgme_data_t_p()
        try:
            errorcheck(gpgme.gpgme_data_new_from_file(tmp, filename, copy))
        except errors.GPGMEError as e:
            if e.getcode() == errors.INV_VALUE and not copy:
                raise ValueError("delayed reads are not yet supported")
            else:
                raise e
        self.wrapped = gpgme.gpgme_data_t_p_value(tmp)
        gpgme.delete_gpgme_data_t_p(tmp)

    def new_from_cbs(self, read_cb, write_cb, seek_cb, release_cb, hook=None):
        tmp = gpgme.new_gpgme_data_t_p()
        if hook != None:
            hookdata = (weakref.ref(self),
                        read_cb, write_cb, seek_cb, release_cb, hook)
        else:
            hookdata = (weakref.ref(self),
                        read_cb, write_cb, seek_cb, release_cb)
        gpgme.pyme_data_new_from_cbs(self, hookdata, tmp)
        self.wrapped = gpgme.gpgme_data_t_p_value(tmp)
        gpgme.delete_gpgme_data_t_p(tmp)

    def new_from_filepart(self, file, offset, length):
        """This wraps the GPGME gpgme_data_new_from_filepart() function.
        The argument "file" may be:

        * a string specifying a file name, or
        * a file-like object supporting the fileno() and the mode attribute.

        """

        tmp = gpgme.new_gpgme_data_t_p()
        filename = None
        fp = None

        if util.is_a_string(file):
            filename = file
        else:
            fp = gpgme.fdopen(file.fileno(), file.mode)
            if fp == None:
                raise ValueError("Failed to open file from %s arg %s" % \
                      (str(type(file)), str(file)))

        errorcheck(gpgme.gpgme_data_new_from_filepart(tmp, filename, fp,
                                                      offset, length))
        self.wrapped = gpgme.gpgme_data_t_p_value(tmp)
        gpgme.delete_gpgme_data_t_p(tmp)

    def new_from_fd(self, file):
        """This wraps the GPGME gpgme_data_new_from_fd() function.  The
        argument "file" must be a file-like object, supporting the
        fileno() method.

        """
        tmp = gpgme.new_gpgme_data_t_p()
        errorcheck(gpgme.gpgme_data_new_from_fd(tmp, file.fileno()))
        self.wrapped = gpgme.gpgme_data_t_p_value(tmp)
        gpgme.delete_gpgme_data_t_p(tmp)

    def new_from_stream(self, file):
        """This wrap around gpgme_data_new_from_stream is an alias for
        new_from_fd() method since in python there's not difference
        between file stream and file descriptor"""
        self.new_from_fd(file)

    def write(self, buffer):
        """Write buffer given as string or bytes.

        If a string is given, it is implicitly encoded using UTF-8."""
        written = gpgme.gpgme_data_write(self.wrapped, buffer)
        if written < 0:
            if self._callback_excinfo:
                gpgme.pyme_raise_callback_exception(self)
            else:
                raise GPGMEError.fromSyserror()
        return written

    def read(self, size = -1):
        """Read at most size bytes, returned as bytes.

        If the size argument is negative or omitted, read until EOF is reached.

        Returns the data read, or the empty string if there was no data
        to read before EOF was reached."""

        if size == 0:
            return ''

        if size > 0:
            try:
                result = gpgme.gpgme_data_read(self.wrapped, size)
            except:
                if self._callback_excinfo:
                    gpgme.pyme_raise_callback_exception(self)
                else:
                    raise
            return result
        else:
            chunks = []
            while True:
                try:
                    result = gpgme.gpgme_data_read(self.wrapped, 4096)
                except:
                    if self._callback_excinfo:
                        gpgme.pyme_raise_callback_exception(self)
                    else:
                        raise
                if len(result) == 0:
                    break
                chunks.append(result)
            return b''.join(chunks)

def pubkey_algo_name(algo):
    return gpgme.gpgme_pubkey_algo_name(algo)

def hash_algo_name(algo):
    return gpgme.gpgme_hash_algo_name(algo)

def get_protocol_name(proto):
    return gpgme.gpgme_get_protocol_name(proto)

def check_version(version=None):
    return gpgme.gpgme_check_version(version)

# check_version also makes sure that several subsystems are properly
# initialized, and it must be run at least once before invoking any
# other function.  We do it here so that the user does not have to do
# it unless she really wants to check for a certain version.
check_version()

def engine_check_version (proto):
    try:
        errorcheck(gpgme.gpgme_engine_check_version(proto))
        return True
    except errors.GPGMEError:
        return False

def get_engine_info():
    ptr = gpgme.new_gpgme_engine_info_t_p()
    try:
        errorcheck(gpgme.gpgme_get_engine_info(ptr))
        info = gpgme.gpgme_engine_info_t_p_value(ptr)
    except errors.GPGMEError:
        info = None
    gpgme.delete_gpgme_engine_info_t_p(ptr)
    return info

def set_engine_info(proto, file_name, home_dir=None):
    """Changes the default configuration of the crypto engine implementing
    the protocol 'proto'. 'file_name' is the file name of
    the executable program implementing this protocol. 'home_dir' is the
    directory name of the configuration directory (engine's default is
    used if omitted)."""
    errorcheck(gpgme.gpgme_set_engine_info(proto, file_name, home_dir))

def set_locale(category, value):
    """Sets the default locale used by contexts"""
    errorcheck(gpgme.gpgme_set_locale(None, category, value))

def wait(hang):
    """Wait for asynchronous call on any Context  to finish.
    Wait forever if hang is True.

    For finished anynch calls it returns a tuple (status, context):
        status  - status return by asnynchronous call.
        context - context which caused this call to return.

    Please read the GPGME manual of more information."""
    ptr = gpgme.new_gpgme_error_t_p()
    context = gpgme.gpgme_wait(None, ptr, hang)
    status = gpgme.gpgme_error_t_p_value(ptr)
    gpgme.delete_gpgme_error_t_p(ptr)
    if context == None:
        errorcheck(status)
    else:
        context = Context(context)
    return (status, context)
