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

import re
import weakref
from . import pygpgme
from .errors import errorcheck, GPGMEError
from . import constants
from . import errors

class GpgmeWrapper(object):
    """Base wrapper class

    Not to be instantiated directly.

    """

    def __init__(self, wrapped):
        self._callback_excinfo = None
        self.wrapped = wrapped

    def __repr__(self):
        return '<{}/{!r}>'.format(super().__repr__(), self.wrapped)

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
        get_func = getattr(pygpgme,
                           "{}get_{}".format(self._cprefix, key))
        set_func = getattr(pygpgme,
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
        func = getattr(pygpgme, name)

        if self._errorcheck(name):
            def _funcwrap(slf, *args):
                result = func(slf.wrapped, *args)
                if slf._callback_excinfo:
                    pygpgme.pygpgme_raise_callback_exception(slf)
                return errorcheck(result, "Invocation of " + name)
        else:
            def _funcwrap(slf, *args):
                result = func(slf.wrapped, *args)
                if slf._callback_excinfo:
                    pygpgme.pygpgme_raise_callback_exception(slf)
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
            super().__setattr__(key, value)

class Context(GpgmeWrapper):
    """Context for cryptographic operations

    All cryptographic operations in GPGME are performed within a
    context, which contains the internal state of the operation as
    well as configuration parameters.  By using several contexts you
    can run several cryptographic operations in parallel, with
    different configuration.

    Access to a context must be synchronized.

    """

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

    _ctype = 'gpgme_ctx_t'
    _cprefix = 'gpgme_'

    def _errorcheck(self, name):
        """This function should list all functions returning gpgme_error_t"""
        if (name.startswith('gpgme_op_') and \
            not name.endswith('_result')) or \
            name == 'gpgme_signers_add' or \
            name == 'gpgme_set_locale' or \
            name == 'gpgme_set_keylist_mode' or \
            name == 'gpgme_set_protocol':
            return 1
        return 0

    _boolean_properties = {'armor', 'textmode', 'offline'}
    def __init__(self, armor=False, textmode=False, offline=False,
                 signers=[], pinentry_mode=constants.PINENTRY_MODE_DEFAULT,
                 wrapped=None):
        """Construct a context object

        Keyword arguments:
        armor		-- enable ASCII armoring (default False)
        textmode	-- enable canonical text mode (default False)
        offline		-- do not contact external key sources (default False)
        signers		-- list of keys used for signing (default [])
        pinentry_mode	-- pinentry mode (default PINENTRY_MODE_DEFAULT)
        """
        if wrapped:
            self.own = False
        else:
            tmp = pygpgme.new_gpgme_ctx_t_p()
            errorcheck(pygpgme.gpgme_new(tmp))
            wrapped = pygpgme.gpgme_ctx_t_p_value(tmp)
            pygpgme.delete_gpgme_ctx_t_p(tmp)
            self.own = True
        super().__init__(wrapped)
        self.armor = armor
        self.textmode = textmode
        self.offline = offline
        self.signers = signers
        self.pinentry_mode = pinentry_mode

    def __del__(self):
        if not pygpgme:
            # At interpreter shutdown, pygpgme is set to NONE.
            return

        self._free_passcb()
        self._free_progresscb()
        self._free_statuscb()
        if self.own and self.wrapped and pygpgme.gpgme_release:
            pygpgme.gpgme_release(self.wrapped)
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

    def op_keylist_next(self):
        """Returns the next key in the list created
        by a call to op_keylist_start().  The object returned
        is of type Key."""
        ptr = pygpgme.new_gpgme_key_t_p()
        try:
            errorcheck(pygpgme.gpgme_op_keylist_next(self.wrapped, ptr))
            key = pygpgme.gpgme_key_t_p_value(ptr)
        except errors.GPGMEError as excp:
            key = None
            if excp.getcode() != errors.EOF:
                raise excp
        pygpgme.delete_gpgme_key_t_p(ptr)
        if key:
            key.__del__ = lambda self: pygpgme.gpgme_key_unref(self)
            return key

    def get_key(self, fpr, secret):
        """Return the key corresponding to the fingerprint 'fpr'"""
        ptr = pygpgme.new_gpgme_key_t_p()
        errorcheck(pygpgme.gpgme_get_key(self.wrapped, fpr, ptr, secret))
        key = pygpgme.gpgme_key_t_p_value(ptr)
        pygpgme.delete_gpgme_key_t_p(ptr)
        if key:
            key.__del__ = lambda self: pygpgme.gpgme_key_unref(self)
            return key

    def op_trustlist_all(self, *args, **kwargs):
        self.op_trustlist_start(*args, **kwargs)
        trust = self.ctx.op_trustlist_next()
        while trust:
            yield trust
            trust = self.ctx.op_trustlist_next()

    def op_trustlist_next(self):
        """Returns the next trust item in the list created
        by a call to op_trustlist_start().  The object returned
        is of type TrustItem."""
        ptr = pygpgme.new_gpgme_trust_item_t_p()
        try:
            errorcheck(pygpgme.gpgme_op_trustlist_next(self.wrapped, ptr))
            trust = pygpgme.gpgme_trust_item_t_p_value(ptr)
        except errors.GPGMEError as excp:
            trust = None
            if excp.getcode() != errors.EOF:
                raise
        pygpgme.delete_gpgme_trust_item_t_p(ptr)
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
        pygpgme.pygpgme_set_passphrase_cb(self, hookdata)

    def _free_passcb(self):
        if pygpgme.pygpgme_set_passphrase_cb:
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
        pygpgme.pygpgme_set_progress_cb(self, hookdata)

    def _free_progresscb(self):
        if pygpgme.pygpgme_set_progress_cb:
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
        pygpgme.pygpgme_set_status_cb(self, hookdata)

    def _free_statuscb(self):
        if pygpgme.pygpgme_set_status_cb:
            self.set_status_cb(None)

    def get_engine_info(self):
        """Returns this context specific engine info"""
        return pygpgme.gpgme_ctx_get_engine_info(self.wrapped)

    def set_engine_info(self, proto, file_name, home_dir=None):
        """Changes the configuration of the crypto engine implementing the
    protocol 'proto' for the context. 'file_name' is the file name of
    the executable program implementing this protocol. 'home_dir' is the
    directory name of the configuration directory (engine's default is
    used if omitted)."""
        errorcheck(pygpgme.gpgme_ctx_set_engine_info(self.wrapped, proto, file_name, home_dir))

    def wait(self, hang):
        """Wait for asynchronous call to finish. Wait forever if hang is True.
        Raises an exception on errors.

        Please read the GPGME manual for more information.

        """
        ptr = pygpgme.new_gpgme_error_t_p()
        pygpgme.gpgme_wait(self.wrapped, ptr, hang)
        status = pygpgme.gpgme_error_t_p_value(ptr)
        pygpgme.delete_gpgme_error_t_p(ptr)
        errorcheck(status)

    def op_edit(self, key, func, fnc_value, out):
        """Start key editing using supplied callback function"""
        if key == None:
            raise ValueError("op_edit: First argument cannot be None")
        if fnc_value:
            opaquedata = (weakref.ref(self), func, fnc_value)
        else:
            opaquedata = (weakref.ref(self), func)

        result = pygpgme.gpgme_op_edit(self.wrapped, key, opaquedata, out)
        if self._callback_excinfo:
            pygpgme.pygpgme_raise_callback_exception(self)
        errorcheck(result)

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
        super().__init__(None)
        self.data_cbs = None

        if cbs != None:
            self.new_from_cbs(*cbs)
        elif string != None:
            self.new_from_mem(string, copy)
        elif file != None and offset != None and length != None:
            self.new_from_filepart(file, offset, length)
        elif file != None:
            if type(file) == type("x"):
                self.new_from_file(file, copy)
            else:
                self.new_from_fd(file)
        else:
            self.new()

    def __del__(self):
        if not pygpgme:
            # At interpreter shutdown, pygpgme is set to NONE.
            return

        if self.wrapped != None and pygpgme.gpgme_data_release:
            pygpgme.gpgme_data_release(self.wrapped)
            if self._callback_excinfo:
                pygpgme.pygpgme_raise_callback_exception(self)
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
        tmp = pygpgme.new_gpgme_data_t_p()
        errorcheck(pygpgme.gpgme_data_new(tmp))
        self.wrapped = pygpgme.gpgme_data_t_p_value(tmp)
        pygpgme.delete_gpgme_data_t_p(tmp)

    def new_from_mem(self, string, copy=True):
        tmp = pygpgme.new_gpgme_data_t_p()
        errorcheck(pygpgme.gpgme_data_new_from_mem(tmp,string,len(string),copy))
        self.wrapped = pygpgme.gpgme_data_t_p_value(tmp)
        pygpgme.delete_gpgme_data_t_p(tmp)

    def new_from_file(self, filename, copy=True):
        tmp = pygpgme.new_gpgme_data_t_p()
        try:
            errorcheck(pygpgme.gpgme_data_new_from_file(tmp, filename, copy))
        except errors.GPGMEError as e:
            if e.getcode() == errors.INV_VALUE and not copy:
                raise ValueError("delayed reads are not yet supported")
            else:
                raise e
        self.wrapped = pygpgme.gpgme_data_t_p_value(tmp)
        pygpgme.delete_gpgme_data_t_p(tmp)

    def new_from_cbs(self, read_cb, write_cb, seek_cb, release_cb, hook=None):
        tmp = pygpgme.new_gpgme_data_t_p()
        if hook != None:
            hookdata = (weakref.ref(self),
                        read_cb, write_cb, seek_cb, release_cb, hook)
        else:
            hookdata = (weakref.ref(self),
                        read_cb, write_cb, seek_cb, release_cb)
        pygpgme.pygpgme_data_new_from_cbs(self, hookdata, tmp)
        self.wrapped = pygpgme.gpgme_data_t_p_value(tmp)
        pygpgme.delete_gpgme_data_t_p(tmp)

    def new_from_filepart(self, file, offset, length):
        """This wraps the GPGME gpgme_data_new_from_filepart() function.
        The argument "file" may be:

        * a string specifying a file name, or
        * a file-like object supporting the fileno() and the mode attribute.

        """

        tmp = pygpgme.new_gpgme_data_t_p()
        filename = None
        fp = None

        if type(file) == type("x"):
            filename = file
        else:
            fp = pygpgme.fdopen(file.fileno(), file.mode)
            if fp == None:
                raise ValueError("Failed to open file from %s arg %s" % \
                      (str(type(file)), str(file)))

        errorcheck(pygpgme.gpgme_data_new_from_filepart(tmp, filename, fp,
                                                      offset, length))
        self.wrapped = pygpgme.gpgme_data_t_p_value(tmp)
        pygpgme.delete_gpgme_data_t_p(tmp)

    def new_from_fd(self, file):
        """This wraps the GPGME gpgme_data_new_from_fd() function.  The
        argument "file" must be a file-like object, supporting the
        fileno() method.

        """
        tmp = pygpgme.new_gpgme_data_t_p()
        errorcheck(pygpgme.gpgme_data_new_from_fd(tmp, file.fileno()))
        self.wrapped = pygpgme.gpgme_data_t_p_value(tmp)
        pygpgme.delete_gpgme_data_t_p(tmp)

    def new_from_stream(self, file):
        """This wrap around gpgme_data_new_from_stream is an alias for
        new_from_fd() method since in python there's not difference
        between file stream and file descriptor"""
        self.new_from_fd(file)

    def write(self, buffer):
        """Write buffer given as string or bytes.

        If a string is given, it is implicitly encoded using UTF-8."""
        written = pygpgme.gpgme_data_write(self.wrapped, buffer)
        if written < 0:
            if self._callback_excinfo:
                pygpgme.pygpgme_raise_callback_exception(self)
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
                result = pygpgme.gpgme_data_read(self.wrapped, size)
            except:
                if self._callback_excinfo:
                    pygpgme.pygpgme_raise_callback_exception(self)
                else:
                    raise
            return result
        else:
            chunks = []
            while True:
                try:
                    result = pygpgme.gpgme_data_read(self.wrapped, 4096)
                except:
                    if self._callback_excinfo:
                        pygpgme.pygpgme_raise_callback_exception(self)
                    else:
                        raise
                if len(result) == 0:
                    break
                chunks.append(result)
            return b''.join(chunks)

def pubkey_algo_name(algo):
    return pygpgme.gpgme_pubkey_algo_name(algo)

def hash_algo_name(algo):
    return pygpgme.gpgme_hash_algo_name(algo)

def get_protocol_name(proto):
    return pygpgme.gpgme_get_protocol_name(proto)

def check_version(version=None):
    return pygpgme.gpgme_check_version(version)

# check_version also makes sure that several subsystems are properly
# initialized, and it must be run at least once before invoking any
# other function.  We do it here so that the user does not have to do
# it unless she really wants to check for a certain version.
check_version()

def engine_check_version (proto):
    try:
        errorcheck(pygpgme.gpgme_engine_check_version(proto))
        return True
    except errors.GPGMEError:
        return False

def get_engine_info():
    ptr = pygpgme.new_gpgme_engine_info_t_p()
    try:
        errorcheck(pygpgme.gpgme_get_engine_info(ptr))
        info = pygpgme.gpgme_engine_info_t_p_value(ptr)
    except errors.GPGMEError:
        info = None
    pygpgme.delete_gpgme_engine_info_t_p(ptr)
    return info

def set_engine_info(proto, file_name, home_dir=None):
    """Changes the default configuration of the crypto engine implementing
    the protocol 'proto'. 'file_name' is the file name of
    the executable program implementing this protocol. 'home_dir' is the
    directory name of the configuration directory (engine's default is
    used if omitted)."""
    errorcheck(pygpgme.gpgme_set_engine_info(proto, file_name, home_dir))

def set_locale(category, value):
    """Sets the default locale used by contexts"""
    errorcheck(pygpgme.gpgme_set_locale(None, category, value))

def wait(hang):
    """Wait for asynchronous call on any Context  to finish.
    Wait forever if hang is True.

    For finished anynch calls it returns a tuple (status, context):
        status  - status return by asnynchronous call.
        context - context which caused this call to return.

    Please read the GPGME manual of more information."""
    ptr = pygpgme.new_gpgme_error_t_p()
    context = pygpgme.gpgme_wait(None, ptr, hang)
    status = pygpgme.gpgme_error_t_p_value(ptr)
    pygpgme.delete_gpgme_error_t_p(ptr)
    if context == None:
        errorcheck(status)
    else:
        context = Context(context)
    return (status, context)
