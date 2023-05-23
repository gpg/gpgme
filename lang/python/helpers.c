/*
# Copyright (C) 2016 g10 Code GmbH
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
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <gpgme.h>
#include <stdlib.h>
#include <string.h>
#include "Python.h"

#include "helpers.h"
#include "private.h"

/* Flag specifying whether this is an in-tree build.  */
int gpg_in_tree_build =
#if IN_TREE_BUILD
  1
#else
  0
#endif
  ;

static PyObject *GPGMEError = NULL;

void _gpg_exception_init(void) {
  if (GPGMEError == NULL) {
    PyObject *errors;
    PyObject *from_list = PyList_New(0);
    errors = PyImport_ImportModuleLevel("errors", PyEval_GetGlobals(),
                                        PyEval_GetLocals(), from_list, 1);
    Py_XDECREF(from_list);
    if (errors) {
      GPGMEError=PyDict_GetItemString(PyModule_GetDict(errors), "GPGMEError");
      Py_XINCREF(GPGMEError);
    }
  }
}

static PyObject *
_gpg_raise_exception(gpgme_error_t err)
{
  PyObject *e;

  _gpg_exception_init();
  if (GPGMEError == NULL)
    return PyErr_Format(PyExc_RuntimeError, "Got gpgme_error_t %d", err);

  e = PyObject_CallFunction(GPGMEError, "l", (long) err);
  if (e == NULL)
    return NULL;

  PyErr_SetObject(GPGMEError, e);
  Py_DECREF(e);

  return NULL;	/* raise */
}

gpgme_error_t _gpg_exception2code(void) {
  gpgme_error_t err_status = gpg_error(GPG_ERR_GENERAL);
  if (GPGMEError && PyErr_ExceptionMatches(GPGMEError)) {
    PyObject *type = 0, *value = 0, *traceback = 0;
    PyObject *error = 0;
    PyErr_Fetch(&type, &value, &traceback);
    PyErr_NormalizeException(&type, &value, &traceback);
    error = PyObject_GetAttrString(value, "error");
    err_status = PyLong_AsLong(error);
    Py_DECREF(error);
    PyErr_Restore(type, value, traceback);
  }
  return err_status;
}

/* Exception support for callbacks.  */
#define EXCINFO	"_callback_excinfo"

static void _gpg_stash_callback_exception(PyObject *weak_self)
{
  PyObject *self, *ptype, *pvalue, *ptraceback, *excinfo;

  PyErr_Fetch(&ptype, &pvalue, &ptraceback);
  excinfo = PyTuple_New(3);
  PyTuple_SetItem(excinfo, 0, ptype);

  if (pvalue)
    PyTuple_SetItem(excinfo, 1, pvalue);
  else {
    Py_INCREF(Py_None);
    PyTuple_SetItem(excinfo, 1, Py_None);
  }

  if (ptraceback)
    PyTuple_SetItem(excinfo, 2, ptraceback);
  else {
    Py_INCREF(Py_None);
    PyTuple_SetItem(excinfo, 2, Py_None);
  }

  self = PyWeakref_GetObject(weak_self);
  /* self only has a borrowed reference.  */
  if (self == Py_None) {
    /* This should not happen, as even if we're called from the data
       release callback triggered from the wrappers destructor, the
       object is still alive and hence the weak reference still refers
       to the object.  However, in case this ever changes, not seeing
       any exceptions is worse than having a little extra code, so
       here we go.  */
      fprintf(stderr,
              "Error occurred in callback, but the wrapper object "
              "has been deallocated.\n");
      PyErr_Restore(ptype, pvalue, ptraceback);
      PyErr_Print();
    }
  else
    PyObject_SetAttrString(self, EXCINFO, excinfo);
  Py_DECREF(excinfo);
}

PyObject *gpg_raise_callback_exception(PyObject *self)
{
  PyGILState_STATE state = PyGILState_Ensure();
  PyObject *ptype, *pvalue, *ptraceback, *excinfo;

  if (! PyObject_HasAttrString(self, EXCINFO))
    goto leave;

  excinfo = PyObject_GetAttrString(self, EXCINFO);
  if (! PyTuple_Check(excinfo))
    {
      Py_DECREF(excinfo);
      goto leave;
    }

  ptype = PyTuple_GetItem(excinfo, 0);
  Py_INCREF(excinfo);

  pvalue = PyTuple_GetItem(excinfo, 1);
  if (pvalue == Py_None)
    pvalue = NULL;
  else
    Py_INCREF(pvalue);

  ptraceback = PyTuple_GetItem(excinfo, 2);
  if (ptraceback == Py_None)
    ptraceback = NULL;
  else
    Py_INCREF(ptraceback);

  /* We now have references for the extracted items.  */
  Py_DECREF(excinfo);

  /* Clear the exception information.  It is important to do this
     before setting the error, because setting the attribute may
     execute python code, and the runtime system raises a SystemError
     if an exception is set but values are returned.  */
  Py_INCREF(Py_None);
  PyObject_SetAttrString(self, EXCINFO, Py_None);

  /* Restore exception.  */
  PyErr_Restore(ptype, pvalue, ptraceback);
  PyGILState_Release(state);
  return NULL; /* Raise exception.  */

 leave:
  Py_INCREF(Py_None);
  PyGILState_Release(state);
  return Py_None;
}
#undef EXCINFO

/* Argument conversion.  */

/* Convert object to a pointer to gpgme type, generic version.  */
PyObject *
_gpg_obj2gpgme_t(PyObject *input, const char *objtype, int argnum)
{
  PyObject *pyname = NULL, *pypointer = NULL;
  pyname = PyObject_GetAttrString(input, "_ctype");
  if (pyname && PyUnicode_Check(pyname))
    {
      PyObject *encoded = PyUnicode_AsUTF8String(pyname);
      if (strcmp(PyBytes_AsString(encoded), objtype) != 0)
        {
          PyErr_Format(PyExc_TypeError,
                       "arg %d: Expected value of type %s, but got %s",
                       argnum, objtype, PyBytes_AsString(encoded));
          Py_DECREF(encoded);
          Py_DECREF(pyname);
          return NULL;
        }
      Py_DECREF(encoded);
    }
  else
    return NULL;

  Py_DECREF(pyname);
  pypointer = PyObject_GetAttrString(input, "wrapped");
  if (pypointer == NULL) {
    PyErr_Format(PyExc_TypeError,
		 "arg %d: Use of uninitialized Python object %s",
		 argnum, objtype);
    return NULL;
  }
  return pypointer;
}

/* Convert object to a pointer to gpgme type, version for data
   objects.  Constructs a wrapper Python on the fly e.g. for file-like
   objects with a fileno method, returning it in WRAPPER.  This object
   must be de-referenced when no longer needed.  */
PyObject *
_gpg_obj2gpgme_data_t(PyObject *input, int argnum, gpgme_data_t *wrapper,
                       PyObject **bytesio, Py_buffer *view)
{
  gpgme_error_t err;
  PyObject *data;
  PyObject *fd;

  /* See if it is a file-like object with file number.  */
  fd = PyObject_CallMethod(input, "fileno", NULL);
  if (fd) {
    err = gpgme_data_new_from_fd(wrapper, (int) PyLong_AsLong(fd));
    Py_DECREF(fd);
    if (err)
      return _gpg_raise_exception (err);

    return _gpg_wrap_gpgme_data_t(*wrapper);
  }
  else
    PyErr_Clear();

  /* No?  Maybe it implements the buffer protocol.  */
  data = PyObject_CallMethod(input, "getbuffer", NULL);
  if (data)
    {
      /* Save a reference to input, which seems to be a BytesIO
         object.  */
      Py_INCREF(input);
      *bytesio = input;
    }
  else
    {
      PyErr_Clear();

      /* No, but maybe the user supplied a buffer object?  */
      data = input;
    }

  /* Do we have a buffer object?  */
  if (PyObject_CheckBuffer(data))
    {
      if (PyObject_GetBuffer(data, view, PyBUF_SIMPLE) < 0)
        return NULL;

      if (data != input)
        Py_DECREF(data);

      assert (view->obj);
      assert (view->ndim == 1);
      assert (view->shape == NULL);
      assert (view->strides == NULL);
      assert (view->suboffsets == NULL);

      err = gpgme_data_new_from_mem(wrapper, view->buf, (size_t) view->len, 0);
      if (err)
        return _gpg_raise_exception (err);

      return _gpg_wrap_gpgme_data_t(*wrapper);
    }

  /* As last resort we assume it is a wrapped data object.  */
  if (PyObject_HasAttrString(data, "_ctype"))
    return _gpg_obj2gpgme_t(data, "gpgme_data_t", argnum);

  return PyErr_Format(PyExc_TypeError,
                      "arg %d: expected gpg.Data, file, "
                      "bytes (not string!), or an object "
                      "implementing the buffer protocol. Got: %s. "
                      "If you provided a string, try to encode() it.",
                      argnum, data->ob_type->tp_name);
}



PyObject *
_gpg_wrap_result(PyObject *fragile, const char *classname)
{
  static PyObject *results;
  PyObject *class;
  PyObject *replacement;

  if (results == NULL)
    {
      PyObject *from_list = PyList_New(0);
      if (from_list == NULL)
        return NULL;

      results = PyImport_ImportModuleLevel("results", PyEval_GetGlobals(),
                                           PyEval_GetLocals(), from_list, 1);
      Py_DECREF(from_list);

      if (results == NULL)
        return NULL;
    }

  class = PyMapping_GetItemString(PyModule_GetDict(results), classname);
  if (class == NULL)
    return NULL;

  replacement = PyObject_CallFunctionObjArgs(class, fragile, NULL);
  Py_DECREF(class);
  return replacement;
}



/* Callback support.  */
static gpgme_error_t pyPassphraseCb(void *hook,
				    const char *uid_hint,
				    const char *passphrase_info,
				    int prev_was_bad,
				    int fd) {
  PyGILState_STATE state = PyGILState_Ensure();
  PyObject *pyhook = (PyObject *) hook;
  PyObject *self = NULL;
  PyObject *func = NULL;
  PyObject *args = NULL;
  PyObject *retval = NULL;
  PyObject *dataarg = NULL;
  PyObject *encoded = NULL;
  gpgme_error_t err_status = 0;

  _gpg_exception_init();

  assert (PyTuple_Check(pyhook));
  assert (PyTuple_Size(pyhook) == 2 || PyTuple_Size(pyhook) == 3);
  self = PyTuple_GetItem(pyhook, 0);
  func = PyTuple_GetItem(pyhook, 1);
  if (PyTuple_Size(pyhook) == 3) {
    dataarg = PyTuple_GetItem(pyhook, 2);
    args = PyTuple_New(4);
  } else {
    args = PyTuple_New(3);
  }

  if (uid_hint == NULL)
    {
      Py_INCREF(Py_None);
      PyTuple_SetItem(args, 0, Py_None);
    }
  else
    PyTuple_SetItem(args, 0, PyUnicode_DecodeUTF8(uid_hint, strlen (uid_hint),
                                                  "strict"));
  if (PyErr_Occurred()) {
    Py_DECREF(args);
    err_status = gpg_error(GPG_ERR_GENERAL);
    goto leave;
  }

  if (passphrase_info == NULL)
    {
      Py_INCREF(Py_None);
      PyTuple_SetItem(args, 1, Py_None);
    }
  else
    PyTuple_SetItem(args, 1, PyUnicode_DecodeUTF8(passphrase_info,
                                                  strlen (passphrase_info),
                                                  "strict"));
  if (PyErr_Occurred()) {
    Py_DECREF(args);
    err_status = gpg_error(GPG_ERR_GENERAL);
    goto leave;
  }

  PyTuple_SetItem(args, 2, PyBool_FromLong((long)prev_was_bad));
  if (dataarg) {
    Py_INCREF(dataarg);		/* Because GetItem doesn't give a ref but SetItem taketh away */
    PyTuple_SetItem(args, 3, dataarg);
  }

  retval = PyObject_CallObject(func, args);
  Py_DECREF(args);
  if (PyErr_Occurred()) {
    err_status = _gpg_exception2code();
  } else {
    if (!retval) {
      if (gpgme_io_writen (fd, "\n", 1) < 0) {
        err_status = gpgme_error_from_syserror ();
        _gpg_raise_exception (err_status);
      }
    } else {
      char *buf;
      size_t len;
      if (PyBytes_Check(retval))
        buf = PyBytes_AsString(retval), len = PyBytes_Size(retval);
      else if (PyUnicode_Check(retval))
        {
          Py_ssize_t ssize;
          encoded = PyUnicode_AsUTF8String(retval);
          if (encoded == NULL)
            {
              err_status = gpg_error(GPG_ERR_GENERAL);
              goto leave;
            }
          if (PyBytes_AsStringAndSize(encoded, &buf, &ssize) == -1)
            {
              err_status = gpg_error(GPG_ERR_GENERAL);
              goto leave;
            }
          assert (! buf || ssize >= 0);
          len = (size_t) ssize;
        }
      else
        {
          PyErr_Format(PyExc_TypeError,
                       "expected str or bytes from passphrase callback, got %s",
                       retval->ob_type->tp_name);
          err_status = gpg_error(GPG_ERR_GENERAL);
          goto leave;
        }

      if (gpgme_io_writen (fd, buf, len) < 0) {
        err_status = gpgme_error_from_syserror ();
        _gpg_raise_exception (err_status);
      }
      if (! err_status && gpgme_io_writen (fd, "\n", 1) < 0) {
        err_status = gpgme_error_from_syserror ();
        _gpg_raise_exception (err_status);
      }

      Py_DECREF(retval);
    }
  }

 leave:
  if (err_status)
    _gpg_stash_callback_exception(self);

  Py_XDECREF(encoded);
  PyGILState_Release(state);
  return err_status;
}

PyObject *
gpg_set_passphrase_cb(PyObject *self, PyObject *cb) {
  PyGILState_STATE state = PyGILState_Ensure();
  PyObject *wrapped;
  gpgme_ctx_t ctx;

  wrapped = PyObject_GetAttrString(self, "wrapped");
  if (wrapped == NULL)
    {
      assert (PyErr_Occurred ());
      PyGILState_Release(state);
      return NULL;
    }

  ctx = _gpg_unwrap_gpgme_ctx_t(wrapped);
  Py_DECREF(wrapped);
  if (ctx == NULL)
    {
      if (cb == Py_None)
        goto out;
      else
        return PyErr_Format(PyExc_RuntimeError, "wrapped is NULL");
    }

  if (cb == Py_None) {
    gpgme_set_passphrase_cb(ctx, NULL, NULL);
    PyObject_SetAttrString(self, "_passphrase_cb", Py_None);
    goto out;
  }

  if (! PyTuple_Check(cb))
    return PyErr_Format(PyExc_TypeError, "cb must be a tuple");
  if (PyTuple_Size(cb) != 2 && PyTuple_Size(cb) != 3)
    return PyErr_Format(PyExc_TypeError,
                        "cb must be a tuple of size 2 or 3");

  gpgme_set_passphrase_cb(ctx, (gpgme_passphrase_cb_t) pyPassphraseCb,
                          (void *) cb);
  PyObject_SetAttrString(self, "_passphrase_cb", cb);

 out:
  Py_INCREF(Py_None);
  PyGILState_Release(state);
  return Py_None;
}

static void pyProgressCb(void *hook, const char *what, int type, int current,
			 int total) {
  PyGILState_STATE state = PyGILState_Ensure();
  PyObject *func = NULL, *dataarg = NULL, *args = NULL, *retval = NULL;
  PyObject *pyhook = (PyObject *) hook;
  PyObject *self = NULL;

  assert (PyTuple_Check(pyhook));
  assert (PyTuple_Size(pyhook) == 2 || PyTuple_Size(pyhook) == 3);
  self = PyTuple_GetItem(pyhook, 0);
  func = PyTuple_GetItem(pyhook, 1);
  if (PyTuple_Size(pyhook) == 3) {
    dataarg = PyTuple_GetItem(pyhook, 2);
    args = PyTuple_New(5);
  } else {
    args = PyTuple_New(4);
  }

  PyTuple_SetItem(args, 0, PyUnicode_DecodeUTF8(what, strlen (what),
                                                "strict"));
  if (PyErr_Occurred()) {
    _gpg_stash_callback_exception(self);
    Py_DECREF(args);
    PyGILState_Release(state);
    return;
  }
  PyTuple_SetItem(args, 1, PyLong_FromLong((long) type));
  PyTuple_SetItem(args, 2, PyLong_FromLong((long) current));
  PyTuple_SetItem(args, 3, PyLong_FromLong((long) total));
  if (dataarg) {
    Py_INCREF(dataarg);		/* Because GetItem doesn't give a ref but SetItem taketh away */
    PyTuple_SetItem(args, 4, dataarg);
  }

  retval = PyObject_CallObject(func, args);
  if (PyErr_Occurred())
    _gpg_stash_callback_exception(self);
  Py_DECREF(args);
  Py_XDECREF(retval);
  PyGILState_Release(state);
}

PyObject *
gpg_set_progress_cb(PyObject *self, PyObject *cb) {
  PyGILState_STATE state = PyGILState_Ensure();
  PyObject *wrapped;
  gpgme_ctx_t ctx;

  wrapped = PyObject_GetAttrString(self, "wrapped");
  if (wrapped == NULL)
    {
      assert (PyErr_Occurred ());
      PyGILState_Release(state);
      return NULL;
    }

  ctx = _gpg_unwrap_gpgme_ctx_t(wrapped);
  Py_DECREF(wrapped);
  if (ctx == NULL)
    {
      if (cb == Py_None)
        goto out;
      else
        return PyErr_Format(PyExc_RuntimeError, "wrapped is NULL");
    }

  if (cb == Py_None) {
    gpgme_set_progress_cb(ctx, NULL, NULL);
    PyObject_SetAttrString(self, "_progress_cb", Py_None);
    goto out;
  }

  if (! PyTuple_Check(cb))
    return PyErr_Format(PyExc_TypeError, "cb must be a tuple");
  if (PyTuple_Size(cb) != 2 && PyTuple_Size(cb) != 3)
    return PyErr_Format(PyExc_TypeError,
                        "cb must be a tuple of size 2 or 3");

  gpgme_set_progress_cb(ctx, (gpgme_progress_cb_t) pyProgressCb, (void *) cb);
  PyObject_SetAttrString(self, "_progress_cb", cb);

 out:
  Py_INCREF(Py_None);
  PyGILState_Release(state);
  return Py_None;
}

/* Status callbacks.  */
static gpgme_error_t pyStatusCb(void *hook, const char *keyword,
                                const char *args) {
  PyGILState_STATE state = PyGILState_Ensure();
  gpgme_error_t err = 0;
  PyObject *pyhook = (PyObject *) hook;
  PyObject *self = NULL;
  PyObject *func = NULL;
  PyObject *dataarg = NULL;
  PyObject *pyargs = NULL;
  PyObject *retval = NULL;

  assert (PyTuple_Check(pyhook));
  assert (PyTuple_Size(pyhook) == 2 || PyTuple_Size(pyhook) == 3);
  self = PyTuple_GetItem(pyhook, 0);
  func = PyTuple_GetItem(pyhook, 1);
  if (PyTuple_Size(pyhook) == 3) {
    dataarg = PyTuple_GetItem(pyhook, 2);
    pyargs = PyTuple_New(3);
  } else {
    pyargs = PyTuple_New(2);
  }

  if (keyword)
    PyTuple_SetItem(pyargs, 0, PyUnicode_DecodeUTF8(keyword, strlen (keyword),
                                                    "strict"));
  else
    {
      Py_INCREF(Py_None);
      PyTuple_SetItem(pyargs, 0, Py_None);
    }
  PyTuple_SetItem(pyargs, 1, PyUnicode_DecodeUTF8(args, strlen (args),
                                                "strict"));
  if (PyErr_Occurred()) {
    err = gpg_error(GPG_ERR_GENERAL);
    Py_DECREF(pyargs);
    goto leave;
  }

  if (dataarg) {
    Py_INCREF(dataarg);
    PyTuple_SetItem(pyargs, 2, dataarg);
  }

  retval = PyObject_CallObject(func, pyargs);
  if (PyErr_Occurred())
    err = _gpg_exception2code();
  Py_DECREF(pyargs);
  Py_XDECREF(retval);

 leave:
  if (err)
    _gpg_stash_callback_exception(self);
  PyGILState_Release(state);
  return err;
}

PyObject *
gpg_set_status_cb(PyObject *self, PyObject *cb) {
  PyGILState_STATE state = PyGILState_Ensure();
  PyObject *wrapped;
  gpgme_ctx_t ctx;

  wrapped = PyObject_GetAttrString(self, "wrapped");
  if (wrapped == NULL)
    {
      assert (PyErr_Occurred ());
      PyGILState_Release(state);
      return NULL;
    }

  ctx = _gpg_unwrap_gpgme_ctx_t(wrapped);
  Py_DECREF(wrapped);
  if (ctx == NULL)
    {
      if (cb == Py_None)
        goto out;
      else
        return PyErr_Format(PyExc_RuntimeError, "wrapped is NULL");
    }

  if (cb == Py_None) {
    gpgme_set_status_cb(ctx, NULL, NULL);
    PyObject_SetAttrString(self, "_status_cb", Py_None);
    goto out;
  }

  if (! PyTuple_Check(cb))
    return PyErr_Format(PyExc_TypeError, "cb must be a tuple");
  if (PyTuple_Size(cb) != 2 && PyTuple_Size(cb) != 3)
    return PyErr_Format(PyExc_TypeError,
                        "cb must be a tuple of size 2 or 3");

  gpgme_set_status_cb(ctx, (gpgme_status_cb_t) pyStatusCb, (void *) cb);
  PyObject_SetAttrString(self, "_status_cb", cb);

 out:
  Py_INCREF(Py_None);
  PyGILState_Release(state);
  return Py_None;
}



/* Interact callbacks.  */
gpgme_error_t
_gpg_interact_cb(void *opaque, const char *keyword,
                  const char *args, int fd)
{
  PyGILState_STATE state = PyGILState_Ensure();
  PyObject *func = NULL, *dataarg = NULL, *pyargs = NULL, *retval = NULL;
  PyObject *py_keyword;
  PyObject *pyopaque = (PyObject *) opaque;
  gpgme_error_t err_status = 0;
  PyObject *self = NULL;

  _gpg_exception_init();

  assert (PyTuple_Check(pyopaque));
  assert (PyTuple_Size(pyopaque) == 2 || PyTuple_Size(pyopaque) == 3);
  self = PyTuple_GetItem(pyopaque, 0);
  func = PyTuple_GetItem(pyopaque, 1);
  if (PyTuple_Size(pyopaque) == 3) {
    dataarg = PyTuple_GetItem(pyopaque, 2);
    pyargs = PyTuple_New(3);
  } else {
    pyargs = PyTuple_New(2);
  }

  if (keyword)
    py_keyword = PyUnicode_FromString(keyword);
  else
    {
      Py_INCREF(Py_None);
      py_keyword = Py_None;
    }

  PyTuple_SetItem(pyargs, 0, py_keyword);
  PyTuple_SetItem(pyargs, 1, PyUnicode_FromString(args));
  if (dataarg) {
    Py_INCREF(dataarg);		/* Because GetItem doesn't give a ref but SetItem taketh away */
    PyTuple_SetItem(pyargs, 2, dataarg);
  }

  retval = PyObject_CallObject(func, pyargs);
  Py_DECREF(pyargs);
  if (PyErr_Occurred()) {
    err_status = _gpg_exception2code();
  } else {
    if (fd>=0 && retval && PyUnicode_Check(retval)) {
      PyObject *encoded = NULL;
      char *buffer;
      Py_ssize_t size;

      encoded = PyUnicode_AsUTF8String(retval);
      if (encoded == NULL)
        {
          err_status = gpg_error(GPG_ERR_GENERAL);
          goto leave;
        }
      if (PyBytes_AsStringAndSize(encoded, &buffer, &size) == -1)
        {
          Py_DECREF(encoded);
          err_status = gpg_error(GPG_ERR_GENERAL);
          goto leave;
        }

      if (gpgme_io_writen (fd, buffer, size) < 0) {
        err_status = gpgme_error_from_syserror ();
        _gpg_raise_exception (err_status);
      }
      if (! err_status && gpgme_io_writen (fd, "\n", 1) < 0) {
        err_status = gpgme_error_from_syserror ();
        _gpg_raise_exception (err_status);
      }
      Py_DECREF(encoded);
    }
  }
 leave:
  if (err_status)
    _gpg_stash_callback_exception(self);

  Py_XDECREF(retval);
  PyGILState_Release(state);
  return err_status;
}



/* Data callbacks.  */

/* Read up to SIZE bytes into buffer BUFFER from the data object with
   the handle HOOK.  Return the number of characters read, 0 on EOF
   and -1 on error.  If an error occurs, errno is set.  */
static ssize_t pyDataReadCb(void *hook, void *buffer, size_t size)
{
  PyGILState_STATE state = PyGILState_Ensure();
  ssize_t result;
  PyObject *pyhook = (PyObject *) hook;
  PyObject *self = NULL;
  PyObject *func = NULL;
  PyObject *dataarg = NULL;
  PyObject *pyargs = NULL;
  PyObject *retval = NULL;

  assert (PyTuple_Check(pyhook));
  assert (PyTuple_Size(pyhook) == 5 || PyTuple_Size(pyhook) == 6);

  self = PyTuple_GetItem(pyhook, 0);
  func = PyTuple_GetItem(pyhook, 1);
  if (PyTuple_Size(pyhook) == 6) {
    dataarg = PyTuple_GetItem(pyhook, 5);
    pyargs = PyTuple_New(2);
  } else {
    pyargs = PyTuple_New(1);
  }

  PyTuple_SetItem(pyargs, 0, PyLong_FromSize_t(size));
  if (dataarg) {
    Py_INCREF(dataarg);
    PyTuple_SetItem(pyargs, 1, dataarg);
  }

  retval = PyObject_CallObject(func, pyargs);
  Py_DECREF(pyargs);
  if (PyErr_Occurred()) {
    _gpg_stash_callback_exception(self);
    result = -1;
    goto leave;
  }

  if (! PyBytes_Check(retval)) {
    PyErr_Format(PyExc_TypeError,
                 "expected bytes from read callback, got %s",
                 retval->ob_type->tp_name);
    _gpg_stash_callback_exception(self);
    result = -1;
    goto leave;
  }

  if (PyBytes_Size(retval) > size) {
    PyErr_Format(PyExc_TypeError,
                 "expected %zu bytes from read callback, got %zu",
                 size, PyBytes_Size(retval));
    _gpg_stash_callback_exception(self);
    result = -1;
    goto leave;
  }

  memcpy(buffer, PyBytes_AsString(retval), PyBytes_Size(retval));
  result = PyBytes_Size(retval);

 leave:
  Py_XDECREF(retval);
  PyGILState_Release(state);
  return result;
}

/* Write up to SIZE bytes from buffer BUFFER to the data object with
   the handle HOOK.  Return the number of characters written, or -1
   on error.  If an error occurs, errno is set.  */
static ssize_t pyDataWriteCb(void *hook, const void *buffer, size_t size)
{
  PyGILState_STATE state = PyGILState_Ensure();
  ssize_t result;
  PyObject *pyhook = (PyObject *) hook;
  PyObject *self = NULL;
  PyObject *func = NULL;
  PyObject *dataarg = NULL;
  PyObject *pyargs = NULL;
  PyObject *retval = NULL;

  assert (PyTuple_Check(pyhook));
  assert (PyTuple_Size(pyhook) == 5 || PyTuple_Size(pyhook) == 6);

  self = PyTuple_GetItem(pyhook, 0);
  func = PyTuple_GetItem(pyhook, 2);
  if (PyTuple_Size(pyhook) == 6) {
    dataarg = PyTuple_GetItem(pyhook, 5);
    pyargs = PyTuple_New(2);
  } else {
    pyargs = PyTuple_New(1);
  }

  PyTuple_SetItem(pyargs, 0, PyBytes_FromStringAndSize(buffer, size));
  if (dataarg) {
    Py_INCREF(dataarg);
    PyTuple_SetItem(pyargs, 1, dataarg);
  }

  retval = PyObject_CallObject(func, pyargs);
  Py_DECREF(pyargs);
  if (PyErr_Occurred()) {
    _gpg_stash_callback_exception(self);
    result = -1;
    goto leave;
  }

#if PY_MAJOR_VERSION < 3
  if (PyInt_Check(retval))
    result = PyInt_AsSsize_t(retval);
  else
#endif
  if (PyLong_Check(retval))
    result = PyLong_AsSsize_t(retval);
  else {
    PyErr_Format(PyExc_TypeError,
                 "expected int from write callback, got %s",
                 retval->ob_type->tp_name);
    _gpg_stash_callback_exception(self);
    result = -1;
  }

 leave:
  Py_XDECREF(retval);
  PyGILState_Release(state);
  return result;
}

/* Set the current position from where the next read or write starts
   in the data object with the handle HOOK to OFFSET, relative to
   WHENCE.  Returns the new offset in bytes from the beginning of the
   data object.  */
static off_t pyDataSeekCb(void *hook, off_t offset, int whence)
{
  PyGILState_STATE state = PyGILState_Ensure();
  off_t result;
  PyObject *pyhook = (PyObject *) hook;
  PyObject *self = NULL;
  PyObject *func = NULL;
  PyObject *dataarg = NULL;
  PyObject *pyargs = NULL;
  PyObject *retval = NULL;

  assert (PyTuple_Check(pyhook));
  assert (PyTuple_Size(pyhook) == 5 || PyTuple_Size(pyhook) == 6);

  self = PyTuple_GetItem(pyhook, 0);
  func = PyTuple_GetItem(pyhook, 3);
  if (PyTuple_Size(pyhook) == 6) {
    dataarg = PyTuple_GetItem(pyhook, 5);
    pyargs = PyTuple_New(3);
  } else {
    pyargs = PyTuple_New(2);
  }

#if defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64
  PyTuple_SetItem(pyargs, 0, PyLong_FromLongLong((long long) offset));
#else
  PyTuple_SetItem(pyargs, 0, PyLong_FromLong((long) offset));
#endif
  PyTuple_SetItem(pyargs, 1, PyLong_FromLong((long) whence));
  if (dataarg) {
    Py_INCREF(dataarg);
    PyTuple_SetItem(pyargs, 2, dataarg);
  }

  retval = PyObject_CallObject(func, pyargs);
  Py_DECREF(pyargs);
  if (PyErr_Occurred()) {
    _gpg_stash_callback_exception(self);
    result = -1;
    goto leave;
  }

#if PY_MAJOR_VERSION < 3
  if (PyInt_Check(retval))
    result = PyInt_AsLong(retval);
  else
#endif
  if (PyLong_Check(retval))
#if defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64
    result = PyLong_AsLongLong(retval);
#else
    result = PyLong_AsLong(retval);
#endif
  else {
    PyErr_Format(PyExc_TypeError,
                 "expected int from seek callback, got %s",
                 retval->ob_type->tp_name);
    _gpg_stash_callback_exception(self);
    result = -1;
  }

 leave:
  Py_XDECREF(retval);
  PyGILState_Release(state);
  return result;
}

/* Close the data object with the handle HOOK.  */
static void pyDataReleaseCb(void *hook)
{
  PyGILState_STATE state = PyGILState_Ensure();
  PyObject *pyhook = (PyObject *) hook;
  PyObject *self = NULL;
  PyObject *func = NULL;
  PyObject *dataarg = NULL;
  PyObject *pyargs = NULL;
  PyObject *retval = NULL;

  assert (PyTuple_Check(pyhook));
  assert (PyTuple_Size(pyhook) == 5 || PyTuple_Size(pyhook) == 6);

  self = PyTuple_GetItem(pyhook, 0);
  func = PyTuple_GetItem(pyhook, 4);
  if (PyTuple_Size(pyhook) == 6) {
    dataarg = PyTuple_GetItem(pyhook, 5);
    pyargs = PyTuple_New(1);
  } else {
    pyargs = PyTuple_New(0);
  }

  if (dataarg) {
    Py_INCREF(dataarg);
    PyTuple_SetItem(pyargs, 0, dataarg);
  }

  retval = PyObject_CallObject(func, pyargs);
  Py_XDECREF(retval);
  Py_DECREF(pyargs);
  if (PyErr_Occurred())
    _gpg_stash_callback_exception(self);
  PyGILState_Release(state);
}

PyObject *
gpg_data_new_from_cbs(PyObject *self,
                       PyObject *pycbs,
                       gpgme_data_t *r_data)
{
  PyGILState_STATE state = PyGILState_Ensure();
  static struct gpgme_data_cbs cbs = {
    pyDataReadCb,
    pyDataWriteCb,
    pyDataSeekCb,
    pyDataReleaseCb,
  };
  gpgme_error_t err;

  if (! PyTuple_Check(pycbs))
    return PyErr_Format(PyExc_TypeError, "pycbs must be a tuple");
  if (PyTuple_Size(pycbs) != 5 && PyTuple_Size(pycbs) != 6)
    return PyErr_Format(PyExc_TypeError,
                        "pycbs must be a tuple of size 5 or 6");

  err = gpgme_data_new_from_cbs(r_data, &cbs, (void *) pycbs);
  if (err)
    return _gpg_raise_exception(err);

  PyObject_SetAttrString(self, "_data_cbs", pycbs);

  Py_INCREF(Py_None);
  PyGILState_Release(state);
  return Py_None;
}



/* The assuan callbacks.  */

gpgme_error_t
_gpg_assuan_data_cb (void *hook, const void *data, size_t datalen)
{
  PyGILState_STATE state = PyGILState_Ensure();
  gpgme_error_t err = 0;
  PyObject *pyhook = (PyObject *) hook;
  PyObject *self = NULL;
  PyObject *func = NULL;
  PyObject *py_data = NULL;
  PyObject *retval = NULL;

  assert (PyTuple_Check(pyhook));
  assert (PyTuple_Size(pyhook) == 2);
  self = PyTuple_GetItem(pyhook, 0);
  func = PyTuple_GetItem(pyhook, 1);
  assert (PyCallable_Check(func));

  py_data = PyBytes_FromStringAndSize(data, datalen);
  if (py_data == NULL)
    {
      err = _gpg_exception2code();
      goto leave;
    }

  retval = PyObject_CallFunctionObjArgs(func, py_data, NULL);
  if (PyErr_Occurred())
    err = _gpg_exception2code();
  Py_DECREF(py_data);
  Py_XDECREF(retval);

 leave:
  if (err)
    _gpg_stash_callback_exception(self);
  PyGILState_Release(state);
  return err;
}

gpgme_error_t
_gpg_assuan_inquire_cb (void *hook, const char *name, const char *args,
                         gpgme_data_t *r_data)
{
  PyGILState_STATE state = PyGILState_Ensure();
  gpgme_error_t err = 0;
  PyObject *pyhook = (PyObject *) hook;
  PyObject *self = NULL;
  PyObject *func = NULL;
  PyObject *py_name = NULL;
  PyObject *py_args = NULL;
  PyObject *retval = NULL;

  assert (PyTuple_Check(pyhook));
  assert (PyTuple_Size(pyhook) == 2);
  self = PyTuple_GetItem(pyhook, 0);
  func = PyTuple_GetItem(pyhook, 1);
  assert (PyCallable_Check(func));

  py_name = PyUnicode_FromString(name);
  if (py_name == NULL)
    {
      err = _gpg_exception2code();
      goto leave;
    }

  py_args = PyUnicode_FromString(args);
  if (py_args == NULL)
    {
      err = _gpg_exception2code();
      goto leave;
    }

  retval = PyObject_CallFunctionObjArgs(func, py_name, py_args, NULL);
  if (PyErr_Occurred())
    err = _gpg_exception2code();
  Py_XDECREF(retval);

  /* FIXME: Returning data is not yet implemented.  */
  *r_data = NULL;

 leave:
  Py_XDECREF(py_name);
  Py_XDECREF(py_args);
  if (err)
    _gpg_stash_callback_exception(self);
  PyGILState_Release(state);
  return err;
}

gpgme_error_t
_gpg_assuan_status_cb (void *hook, const char *status, const char *args)
{
  PyGILState_STATE state = PyGILState_Ensure();
  gpgme_error_t err = 0;
  PyObject *pyhook = (PyObject *) hook;
  PyObject *self = NULL;
  PyObject *func = NULL;
  PyObject *py_status = NULL;
  PyObject *py_args = NULL;
  PyObject *retval = NULL;

  assert (PyTuple_Check(pyhook));
  assert (PyTuple_Size(pyhook) == 2);
  self = PyTuple_GetItem(pyhook, 0);
  func = PyTuple_GetItem(pyhook, 1);
  assert (PyCallable_Check(func));

  py_status = PyUnicode_FromString(status);
  if (py_status == NULL)
    {
      err = _gpg_exception2code();
      goto leave;
    }

  py_args = PyUnicode_FromString(args);
  if (py_args == NULL)
    {
      err = _gpg_exception2code();
      goto leave;
    }

  retval = PyObject_CallFunctionObjArgs(func, py_status, py_args, NULL);
  if (PyErr_Occurred())
    err = _gpg_exception2code();
  Py_XDECREF(retval);

 leave:
  Py_XDECREF(py_status);
  Py_XDECREF(py_args);
  if (err)
    _gpg_stash_callback_exception(self);
  PyGILState_Release(state);
  return err;
}
