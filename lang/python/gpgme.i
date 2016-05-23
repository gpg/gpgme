/*
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
*/
%module pygpgme
%include "cpointer.i"
%include "cstring.i"

// Generate doc strings for all methods.
%feature("autodoc", "0");

/* Allow use of Unicode objects, bytes, and None for strings.  */

%typemap(in) const char * {
  if ($input == Py_None)
    $1 = NULL;
  else if (PyUnicode_Check($input))
    $1 = PyUnicode_AsUTF8($input);
  else if (PyBytes_Check($input))
    $1 = PyBytes_AsString($input);
  else {
    PyErr_Format(PyExc_TypeError,
                 "arg %d: expected str, bytes, or None, got %s",
		 $argnum, $input->ob_type->tp_name);
    return NULL;
  }
}
%typemap(freearg) const char * "";

/* Likewise for a list of strings.  */
%typemap(in) const char *[] {
  /* Check if is a list */
  if (PyList_Check($input)) {
    size_t i, size = PyList_Size($input);
    $1 = (char **) malloc((size+1) * sizeof(char *));

    for (i = 0; i < size; i++) {
      PyObject *o = PyList_GetItem($input,i);
      if (PyUnicode_Check(o))
        $1[i] = PyUnicode_AsUTF8(o);
      else if (PyString_Check(o))
	$1[i] = PyString_AsString(o);
      else {
	PyErr_Format(PyExc_TypeError,
                     "arg %d: list must contain only str or bytes, got %s "
                     "at position %d",
                     $argnum, o->ob_type->tp_name, i);
	free($1);
	return NULL;
      }
    }
    $1[i] = NULL;
  } else {
    PyErr_Format(PyExc_TypeError,
                 "arg %d: expected a list of str or bytes, got %s",
                 $argnum, $input->ob_type->tp_name);
    return NULL;
  }
}
%typemap(freearg) const char *[] {
  free((char *) $1);
}

// Release returned buffers as necessary.
%typemap(newfree) char * "free($1);";
%newobject gpgme_data_release_and_get_mem;

%{
/* Convert object to a pointer to gpgme type */
PyObject* object_to_gpgme_t(PyObject* input, const char* objtype, int argnum) {
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
    {
      PyErr_Format(PyExc_TypeError,
                   "Protocol violation: Expected an instance of type str "
                   "from _getctype, but got %s",
                   pyname == NULL ? "NULL"
                   : (pyname == Py_None ? "None" : pyname->ob_type->tp_name));
      return NULL;
    }

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
%}

%typemap(arginit) gpgme_key_t [] {
  $1 = NULL;
}

%typemap(in) gpgme_key_t [] {
  int i, numb = 0;
  if (!PySequence_Check($input)) {
    PyErr_Format(PyExc_ValueError, "arg %d: Expected a list of gpgme_key_t",
		 $argnum);
    return NULL;
  }
  if((numb = PySequence_Length($input)) != 0) {
    $1 = (gpgme_key_t*)malloc((numb+1)*sizeof(gpgme_key_t));
    for(i=0; i<numb; i++) {
      PyObject *pypointer = PySequence_GetItem($input, i);

      /* input = $input, 1 = $1, 1_descriptor = $1_descriptor */
      /* &1_descriptor = $&1_descriptor *1_descriptor = $*1_descriptor */

      // Following code is from swig's python.swg
      if ((SWIG_ConvertPtr(pypointer,(void **) &$1[i], $*1_descriptor,SWIG_POINTER_EXCEPTION | $disown )) == -1) {
	Py_DECREF(pypointer);
	return NULL;
      }
      Py_DECREF(pypointer);
    }
    $1[numb] = NULL;
  }
}
%typemap(freearg) gpgme_key_t [] {
  if ($1) free($1);
}

// Special handling for references to our objects.
%typemap(in) gpgme_data_t DATAIN {
  if ($input == Py_None)
    $1 = NULL;
  else {
    PyObject *pypointer = NULL;

    if((pypointer=object_to_gpgme_t($input, "$1_ltype", $argnum)) == NULL)
      return NULL;

    /* input = $input, 1 = $1, 1_descriptor = $1_descriptor */

    // Following code is from swig's python.swg

    if ((SWIG_ConvertPtr(pypointer,(void **) &$1, $1_descriptor,
         SWIG_POINTER_EXCEPTION | $disown )) == -1) {
      Py_DECREF(pypointer);
      return NULL;
    }
    Py_DECREF(pypointer);
  }
}

%apply gpgme_data_t DATAIN {gpgme_data_t plain, gpgme_data_t cipher,
			gpgme_data_t sig, gpgme_data_t signed_text,
			gpgme_data_t plaintext, gpgme_data_t keydata,
			gpgme_data_t pubkey, gpgme_data_t seckey,
			gpgme_data_t out};

// SWIG has problem interpreting ssize_t, off_t or gpgme_error_t in gpgme.h
%typemap(out) ssize_t, off_t, gpgme_error_t, gpgme_err_code_t, gpgme_err_source_t, gpg_error_t {
  $result = PyLong_FromLong($1);
}
%typemap(in) ssize_t, off_t, gpgme_error_t, gpgme_err_code_t, gpgme_err_source_t, gpg_error_t {
  $1 = PyLong_AsLong($input);
}

// Those are for gpgme_data_read() and gpgme_strerror_r()
%typemap(in) (void *buffer, size_t size), (char *buf, size_t buflen) {
   $2 = PyLong_AsLong($input);
   if ($2 < 0) {
     PyErr_SetString(PyExc_ValueError, "Positive integer expected");
     return NULL;
   }
   $1 = ($1_ltype) malloc($2+1);
}
%typemap(argout) (void *buffer, size_t size), (char *buf, size_t buflen) {
  Py_XDECREF($result);   /* Blow away any previous result */
  if (result < 0) {      /* Check for I/O error */
    free($1);
    return NULL;
  }
  $result = PyBytes_FromStringAndSize($1,result);
  free($1);
}

/* For gpgme_data_write, but should be universal.  */
%typemap(in) (const void *buffer, size_t size) {
  if ($input == Py_None)
    $1 = NULL, $2 = 0;
  else if (PyUnicode_Check($input))
    $1 = PyUnicode_AsUTF8AndSize($input, (size_t *) &$2);
  else if (PyBytes_Check($input))
    PyBytes_AsStringAndSize($input, (char **) &$1, (size_t *) &$2);
  else {
    PyErr_Format(PyExc_TypeError,
                 "arg %d: expected str, bytes, or None, got %s",
		 $argnum, $input->ob_type->tp_name);
    return NULL;
  }
}
%typemap(freearg) (const void *buffer, size_t size) "";

// Make types containing 'next' field to be lists
%ignore next;
%typemap(out) gpgme_sig_notation_t, gpgme_engine_info_t, gpgme_subkey_t, gpgme_key_sig_t,
	gpgme_user_id_t, gpgme_invalid_key_t, gpgme_recipient_t, gpgme_new_signature_t,
	gpgme_signature_t, gpgme_import_status_t, gpgme_conf_arg_t, gpgme_conf_opt_t,
	gpgme_conf_comp_t {
  int i;
  int size = 0;
  $1_ltype curr;
  for (curr = $1; curr != NULL; curr = curr->next) {
    size++;
  }
  $result = PyList_New(size);
  for (i=0,curr=$1; i<size; i++,curr=curr->next) {
    PyObject *o = SWIG_NewPointerObj(SWIG_as_voidptr(curr), $1_descriptor, %newpointer_flags);
    PyList_SetItem($result, i, o);
  }
}

// Include mapper for edit callbacks
%typemap(in) (gpgme_edit_cb_t fnc, void *fnc_value) {
  $1 = (gpgme_edit_cb_t) pyEditCb;
  if ($input == Py_None)
    $2 = NULL;
  else
    $2 = $input;
}

// Include the header file both for cc (first) and for swig (second)
// Include for swig locally since we need to fix 'class' usage there.
%{
#include <gpgme.h>
%}
%include "gpgme.h"

%constant long EOF = GPG_ERR_EOF;

// Generating and handling pointers-to-pointers.

%pointer_functions(gpgme_ctx_t, gpgme_ctx_t_p);
%pointer_functions(gpgme_data_t, gpgme_data_t_p);
%pointer_functions(gpgme_key_t, gpgme_key_t_p);
%pointer_functions(gpgme_error_t, gpgme_error_t_p);
%pointer_functions(gpgme_trust_item_t, gpgme_trust_item_t_p);
%pointer_functions(gpgme_engine_info_t, gpgme_engine_info_t_p);
%pointer_functions(PyObject *, PyObject_p_p);
%pointer_functions(void *, void_p_p);

// Helper functions.

%{
#include <stdio.h>
%}
FILE *fdopen(int fildes, const char *mode);

%{
#include "helpers.h"
%}
%include "helpers.h"

%{
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
%}
