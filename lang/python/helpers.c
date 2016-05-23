/*
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

static void pygpgme_stash_callback_exception(PyObject *self)
{
  PyObject *ptype, *pvalue, *ptraceback, *excinfo;

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

  PyObject_SetAttrString(self, EXCINFO, excinfo);
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
      write(fd, "\n", 1);
    } else {
      char *buf;
      size_t len;
      if (PyBytes_Check(retval))
        buf = PyBytes_AsString(retval), len = PyBytes_Size(retval);
      else if (PyUnicode_Check(retval))
        buf = PyUnicode_AsUTF8AndSize(retval, &len);
      else
        {
          PyErr_Format(PyExc_TypeError,
                       "expected str or bytes from passphrase callback, got %s",
                       retval->ob_type->tp_name);
          err_status = gpg_error(GPG_ERR_GENERAL);
          goto leave;
        }

      write(fd, buf, len);
      write(fd, "\n", 1);
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


/* Edit callbacks.  */
gpgme_error_t pyEditCb(void *opaque, gpgme_status_code_t status,
		       const char *args, int fd) {
  PyObject *func = NULL, *dataarg = NULL, *pyargs = NULL, *retval = NULL;
  PyObject *pyopaque = (PyObject *) opaque;
  gpgme_error_t err_status = 0;

  pygpgme_exception_init();

  if (PyTuple_Check(pyopaque)) {
    func = PyTuple_GetItem(pyopaque, 0);
    dataarg = PyTuple_GetItem(pyopaque, 1);
    pyargs = PyTuple_New(3);
  } else {
    func = pyopaque;
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
      write(fd, buffer, size);
      write(fd, "\n", 1);
    }
  }

  Py_XDECREF(retval);
  return err_status;
}
