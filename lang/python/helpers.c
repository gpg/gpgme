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
    errors = PyImport_ImportModule("errors");
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

static gpgme_error_t pyPassphraseCb(void *hook,
				    const char *uid_hint,
				    const char *passphrase_info,
				    int prev_was_bad,
				    int fd) {
  PyObject *pyhook = (PyObject *) hook;
  PyObject *func = NULL;
  PyObject *args = NULL;
  PyObject *retval = NULL;
  PyObject *dataarg = NULL;
  gpgme_error_t err_status = 0;  

  pygpgme_exception_init();

  if (PyTuple_Check(pyhook)) {
    func = PyTuple_GetItem(pyhook, 0);
    dataarg = PyTuple_GetItem(pyhook, 1);
    args = PyTuple_New(4);
  } else {
    func = pyhook;
    args = PyTuple_New(3);
  }

  PyTuple_SetItem(args, 0, PyBytes_FromString(uid_hint));
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
      write(fd, PyBytes_AsString(retval), PyBytes_Size(retval));
      write(fd, "\n", 1);
      Py_DECREF(retval);
    }
  }

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
  
  if (PyTuple_Check(pyhook)) {
    func = PyTuple_GetItem(pyhook, 0);
    dataarg = PyTuple_GetItem(pyhook, 1);
    args = PyTuple_New(5);
  } else {
    func = pyhook;
    args = PyTuple_New(4);
  }

  PyTuple_SetItem(args, 0, PyBytes_FromString(what));
  PyTuple_SetItem(args, 1, PyLong_FromLong((long) type));
  PyTuple_SetItem(args, 2, PyLong_FromLong((long) current));
  PyTuple_SetItem(args, 3, PyLong_FromLong((long) total));
  if (dataarg) {
    Py_INCREF(dataarg);		/* Because GetItem doesn't give a ref but SetItem taketh away */
    PyTuple_SetItem(args, 4, dataarg);
  }
  
  retval = PyObject_CallObject(func, args);
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
