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

#include <assert.h>
#include <stdio.h>
#include <gpgme.h>
#include <stdlib.h>
#include <string.h>
#include "Python.h"
#include "helpers.h"

static PyObject *GPGMEError = NULL;

void pygpgme_exception_init(void) {
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
pygpgme_raise_exception(gpgme_error_t err)
{
  PyObject *e;

  pygpgme_exception_init();
  if (GPGMEError == NULL)
    return PyErr_Format(PyExc_RuntimeError, "Got gpgme_error_t %d", err);

  e = PyObject_CallFunction(GPGMEError, "l", (long) err);
  if (e == NULL)
    return NULL;

  PyErr_SetObject(GPGMEError, e);
  Py_DECREF(e);

  return NULL;	/* raise */
}

gpgme_error_t pygpgme_exception2code(void) {
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

void pygpgme_clear_generic_cb(PyObject **cb) {
  Py_DECREF(*cb);
}

/* Exception support for callbacks.  */
#define EXCINFO	"_callback_excinfo"

static void pygpgme_stash_callback_exception(PyObject *weak_self)
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

PyObject *pygpgme_raise_callback_exception(PyObject *self)
{
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

  Py_DECREF(excinfo);
  PyErr_Restore(ptype, pvalue, ptraceback);

  Py_INCREF(Py_None);
  PyObject_SetAttrString(self, EXCINFO, Py_None);

  return NULL; /* Raise exception.  */

 leave:
  Py_INCREF(Py_None);
  return Py_None;
}
#undef EXCINFO

/* Argument conversion.  */

/* Convert object to a pointer to gpgme type, generic version.  */
PyObject *
object_to_gpgme_t(PyObject *input, const char *objtype, int argnum)
{
  PyObject *pyname = NULL, *pypointer = NULL;
  pyname = PyObject_CallMethod(input, "_getctype", NULL);
  if (pyname && PyUnicode_Check(pyname))
    {
      if (strcmp(PyUnicode_AsUTF8(pyname), objtype) != 0)
        {
          PyErr_Format(PyExc_TypeError,
                       "arg %d: Expected value of type %s, but got %s",
                       argnum, objtype, PyUnicode_AsUTF8(pyname));
          Py_DECREF(pyname);
          return NULL;
        }
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
object_to_gpgme_data_t(PyObject *input, int argnum, PyObject **wrapper)
{
  static PyObject *Data = NULL;
  PyObject *data = input;
  PyObject *fd;
  PyObject *result;
  *wrapper = NULL;

  if (Data == NULL) {
    PyObject *core;
    PyObject *from_list = PyList_New(0);
    core = PyImport_ImportModuleLevel("core", PyEval_GetGlobals(),
                                      PyEval_GetLocals(), from_list, 1);
    Py_XDECREF(from_list);
    if (core) {
      Data = PyDict_GetItemString(PyModule_GetDict(core), "Data");
      Py_XINCREF(Data);
    }
    else
      return NULL;
  }

  fd = PyObject_CallMethod(input, "fileno", NULL);
  if (fd) {
    /* File-like object with file number.  */
    PyObject *args = NULL;
    PyObject *kw = NULL;

    /* We don't need the fd, as we have no constructor accepting file
       descriptors directly.  */
    Py_DECREF(fd);

    args = PyTuple_New(0);
    kw = PyDict_New();
    if (args == NULL || kw == NULL)
      {
      fail:
        Py_XDECREF(args);
        Py_XDECREF(kw);
        return NULL;
      }

    if (PyDict_SetItemString(kw, "file", input) < 0)
      goto fail;

    *wrapper = PyObject_Call(Data, args, kw);
    if (*wrapper == NULL)
      goto fail;

    Py_DECREF(args);
    Py_DECREF(kw);
    data = *wrapper;
  }
  else
    PyErr_Clear();

  result = object_to_gpgme_t(data, "gpgme_data_t", argnum);
  return result;
}



/* Callback support.  */
static gpgme_error_t pyPassphraseCb(void *hook,
				    const char *uid_hint,
				    const char *passphrase_info,
				    int prev_was_bad,
				    int fd) {
  PyObject *pyhook = (PyObject *) hook;
  PyObject *self = NULL;
  PyObject *func = NULL;
  PyObject *args = NULL;
  PyObject *retval = NULL;
  PyObject *dataarg = NULL;
  gpgme_error_t err_status = 0;

  pygpgme_exception_init();

  assert (PyTuple_Check(pyhook));
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

  PyTuple_SetItem(args, 1, PyBytes_FromString(passphrase_info));
  PyTuple_SetItem(args, 2, PyBool_FromLong((long)prev_was_bad));
  if (dataarg) {
    Py_INCREF(dataarg);		/* Because GetItem doesn't give a ref but SetItem taketh away */
    PyTuple_SetItem(args, 3, dataarg);
  }

  retval = PyObject_CallObject(func, args);
  Py_DECREF(args);
  if (PyErr_Occurred()) {
    err_status = pygpgme_exception2code();
  } else {
    if (!retval) {
      if (write(fd, "\n", 1) < 0) {
        err_status = gpgme_error_from_syserror ();
        pygpgme_raise_exception (err_status);
      }
    } else {
      char *buf;
      size_t len;
      if (PyBytes_Check(retval))
        buf = PyBytes_AsString(retval), len = PyBytes_Size(retval);
      else if (PyUnicode_Check(retval))
        {
          Py_ssize_t ssize;
          buf = PyUnicode_AsUTF8AndSize(retval, &ssize);
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

      if (write(fd, buf, len) < 0) {
        err_status = gpgme_error_from_syserror ();
        pygpgme_raise_exception (err_status);
      }
      if (! err_status && write(fd, "\n", 1) < 0) {
        err_status = gpgme_error_from_syserror ();
        pygpgme_raise_exception (err_status);
      }

      Py_DECREF(retval);
    }
  }

 leave:
  if (err_status)
    pygpgme_stash_callback_exception(self);

  return err_status;
}

void pygpgme_set_passphrase_cb(gpgme_ctx_t ctx, PyObject *cb,
			       PyObject **freelater) {
  if (cb == Py_None) {
    gpgme_set_passphrase_cb(ctx, NULL, NULL);
    return;
  }
  Py_INCREF(cb);
  *freelater = cb;
  gpgme_set_passphrase_cb(ctx, (gpgme_passphrase_cb_t)pyPassphraseCb, (void *) cb);
}

static void pyProgressCb(void *hook, const char *what, int type, int current,
			 int total) {
  PyObject *func = NULL, *dataarg = NULL, *args = NULL, *retval = NULL;
  PyObject *pyhook = (PyObject *) hook;
  PyObject *self = NULL;

  assert (PyTuple_Check(pyhook));
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
    pygpgme_stash_callback_exception(self);
    Py_DECREF(args);
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
    pygpgme_stash_callback_exception(self);
  Py_DECREF(args);
  Py_XDECREF(retval);
}

void pygpgme_set_progress_cb(gpgme_ctx_t ctx, PyObject *cb, PyObject **freelater){
  if (cb == Py_None) {
    gpgme_set_progress_cb(ctx, NULL, NULL);
    return;
  }
  Py_INCREF(cb);
  *freelater = cb;
  gpgme_set_progress_cb(ctx, (gpgme_progress_cb_t) pyProgressCb, (void *) cb);
}

/* Status callbacks.  */
static gpgme_error_t pyStatusCb(void *hook, const char *keyword,
                                const char *args) {
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
    err = pygpgme_exception2code();
  Py_DECREF(pyargs);
  Py_XDECREF(retval);

 leave:
  if (err)
    pygpgme_stash_callback_exception(self);
  return err;
}

void pygpgme_set_status_cb(gpgme_ctx_t ctx, PyObject *cb,
                           PyObject **freelater) {
  if (cb == Py_None) {
    gpgme_set_status_cb(ctx, NULL, NULL);
    return;
  }
  Py_INCREF(cb);
  *freelater = cb;
  gpgme_set_status_cb(ctx, (gpgme_status_cb_t) pyStatusCb, (void *) cb);
}

/* Edit callbacks.  */
gpgme_error_t pyEditCb(void *opaque, gpgme_status_code_t status,
		       const char *args, int fd) {
  PyObject *func = NULL, *dataarg = NULL, *pyargs = NULL, *retval = NULL;
  PyObject *pyopaque = (PyObject *) opaque;
  gpgme_error_t err_status = 0;
  PyObject *self = NULL;

  pygpgme_exception_init();

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

  PyTuple_SetItem(pyargs, 0, PyLong_FromLong((long) status));
  PyTuple_SetItem(pyargs, 1, PyUnicode_FromString(args));
  if (dataarg) {
    Py_INCREF(dataarg);		/* Because GetItem doesn't give a ref but SetItem taketh away */
    PyTuple_SetItem(pyargs, 2, dataarg);
  }

  retval = PyObject_CallObject(func, pyargs);
  Py_DECREF(pyargs);
  if (PyErr_Occurred()) {
    err_status = pygpgme_exception2code();
  } else {
    if (fd>=0 && retval && PyUnicode_Check(retval)) {
      const char *buffer;
      Py_ssize_t size;

      buffer = PyUnicode_AsUTF8AndSize(retval, &size);
      if (write(fd, buffer, size) < 0) {
        err_status = gpgme_error_from_syserror ();
        pygpgme_raise_exception (err_status);
      }
      if (! err_status && write(fd, "\n", 1) < 0) {
        err_status = gpgme_error_from_syserror ();
        pygpgme_raise_exception (err_status);
      }
    }
  }
  if (err_status)
    pygpgme_stash_callback_exception(self);

  Py_XDECREF(retval);
  return err_status;
}

/* Data callbacks.  */

/* Read up to SIZE bytes into buffer BUFFER from the data object with
   the handle HOOK.  Return the number of characters read, 0 on EOF
   and -1 on error.  If an error occurs, errno is set.  */
static ssize_t pyDataReadCb(void *hook, void *buffer, size_t size)
{
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
    pygpgme_stash_callback_exception(self);
    result = -1;
    goto leave;
  }

  if (! PyBytes_Check(retval)) {
    PyErr_Format(PyExc_TypeError,
                 "expected bytes from read callback, got %s",
                 retval->ob_type->tp_name);
    pygpgme_stash_callback_exception(self);
    result = -1;
    goto leave;
  }

  if (PyBytes_Size(retval) > size) {
    PyErr_Format(PyExc_TypeError,
                 "expected %zu bytes from read callback, got %zu",
                 size, PyBytes_Size(retval));
    pygpgme_stash_callback_exception(self);
    result = -1;
    goto leave;
  }

  memcpy(buffer, PyBytes_AsString(retval), PyBytes_Size(retval));
  result = PyBytes_Size(retval);

 leave:
  Py_XDECREF(retval);
  return result;
}

/* Write up to SIZE bytes from buffer BUFFER to the data object with
   the handle HOOK.  Return the number of characters written, or -1
   on error.  If an error occurs, errno is set.  */
static ssize_t pyDataWriteCb(void *hook, const void *buffer, size_t size)
{
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
    pygpgme_stash_callback_exception(self);
    result = -1;
    goto leave;
  }

  if (! PyLong_Check(retval)) {
    PyErr_Format(PyExc_TypeError,
                 "expected int from read callback, got %s",
                 retval->ob_type->tp_name);
    pygpgme_stash_callback_exception(self);
    result = -1;
    goto leave;
  }

  result = PyLong_AsSsize_t(retval);

 leave:
  Py_XDECREF(retval);
  return result;
}

/* Set the current position from where the next read or write starts
   in the data object with the handle HOOK to OFFSET, relativ to
   WHENCE.  Returns the new offset in bytes from the beginning of the
   data object.  */
static off_t pyDataSeekCb(void *hook, off_t offset, int whence)
{
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
    pygpgme_stash_callback_exception(self);
    result = -1;
    goto leave;
  }

  if (! PyLong_Check(retval)) {
    PyErr_Format(PyExc_TypeError,
                 "expected int from read callback, got %s",
                 retval->ob_type->tp_name);
    pygpgme_stash_callback_exception(self);
    result = -1;
    goto leave;
  }

#if defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64
  result = PyLong_AsLongLong(retval);
#else
  result = PyLong_AsLong(retval);
#endif

 leave:
  Py_XDECREF(retval);
  return result;
}

/* Close the data object with the handle HOOK.  */
static void pyDataReleaseCb(void *hook)
{
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
    pygpgme_stash_callback_exception(self);
}

gpgme_error_t pygpgme_data_new_from_cbs(gpgme_data_t *r_data,
                                        PyObject *pycbs,
                                        PyObject **freelater)
{
  static struct gpgme_data_cbs cbs = {
    pyDataReadCb,
    pyDataWriteCb,
    pyDataSeekCb,
    pyDataReleaseCb,
  };

  assert (PyTuple_Check(pycbs));
  assert (PyTuple_Size(pycbs) == 5 || PyTuple_Size(pycbs) == 6);

  Py_INCREF(pycbs);
  *freelater = pycbs;

  return gpgme_data_new_from_cbs(r_data, &cbs, (void *) pycbs);
}
