/*
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
%typemap(in) const char *[] (void *vector = NULL) {
  /* Check if is a list */
  if (PyList_Check($input)) {
    size_t i, size = PyList_Size($input);
    $1 = (char **) (vector = malloc((size+1) * sizeof(char *)));

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
  free(vector$argnum);
}

// Release returned buffers as necessary.
%typemap(newfree) char * "free($1);";
%newobject gpgme_data_release_and_get_mem;

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
%typemap(in) gpgme_data_t DATAIN (gpgme_data_t wrapper = NULL,
                                  PyObject *bytesio = NULL, Py_buffer view) {
  /* If we create a temporary wrapper object, we will store it in
     wrapperN, where N is $argnum.  Here in this fragment, SWIG will
     automatically append $argnum.  */
  memset(&view, 0, sizeof view);
  if ($input == Py_None)
    $1 = NULL;
  else {
    PyObject *pypointer;
    pypointer = object_to_gpgme_data_t($input, $argnum, &wrapper,
                                       &bytesio, &view);
    if (pypointer == NULL)
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

%typemap(freearg) gpgme_data_t DATAIN {
  /* See whether we need to update the Python buffer.  */
  if (resultobj && wrapper$argnum && view$argnum.buf
      && wrapper$argnum->data.mem.buffer != NULL)
    {
      /* The buffer is dirty.  */
      if (view$argnum.readonly)
        {
          Py_XDECREF(resultobj);
          resultobj = NULL;
          PyErr_SetString(PyExc_ValueError, "cannot update read-only buffer");
        }

      /* See if we need to truncate the buffer.  */
      if (resultobj && view$argnum.len != wrapper$argnum->data.mem.length)
        {
          if (bytesio$argnum == NULL)
            {
              Py_XDECREF(resultobj);
              resultobj = NULL;
              PyErr_SetString(PyExc_ValueError, "cannot resize buffer");
            }
          else
            {
              PyObject *retval;
              PyBuffer_Release(&view$argnum);
              retval = PyObject_CallMethod(bytesio$argnum, "truncate", "l",
                                           (long)
                                           wrapper$argnum->data.mem.length);
              if (retval == NULL)
                {
                  Py_XDECREF(resultobj);
                  resultobj = NULL;
                }
              else
                {
                  Py_DECREF(retval);

                  retval = PyObject_CallMethod(bytesio$argnum, "getbuffer", NULL);
                  if (retval == NULL
                      || PyObject_GetBuffer(retval, &view$argnum,
                                            PyBUF_SIMPLE|PyBUF_WRITABLE) < 0)
                    {
                      Py_XDECREF(resultobj);
                      resultobj = NULL;
                    }

                  Py_XDECREF(retval);

                  if (resultobj && view$argnum.len
                      != wrapper$argnum->data.mem.length)
                    {
                      Py_XDECREF(resultobj);
                      resultobj = NULL;
                      PyErr_Format(PyExc_ValueError,
                                   "Expected buffer of length %zu, got %zi",
                                   wrapper$argnum->data.mem.length,
                                   view$argnum.len);
                    }
                }
            }
        }

      if (resultobj)
        memcpy(view$argnum.buf, wrapper$argnum->data.mem.buffer,
               wrapper$argnum->data.mem.length);
    }

  /* Free the temporary wrapper, if any.  */
  if (wrapper$argnum)
    gpgme_data_release(wrapper$argnum);
  Py_XDECREF (bytesio$argnum);
  if (wrapper$argnum && view$argnum.buf)
    PyBuffer_Release(&view$argnum);
}

%apply gpgme_data_t DATAIN {gpgme_data_t plain, gpgme_data_t cipher,
			gpgme_data_t sig, gpgme_data_t signed_text,
			gpgme_data_t plaintext, gpgme_data_t keydata,
			gpgme_data_t pubkey, gpgme_data_t seckey,
			gpgme_data_t out};

/* SWIG has problems interpreting ssize_t, off_t or gpgme_error_t in
   gpgme.h.  */
/* XXX: This is wrong at least for off_t if compiled with LFS.  */
%typemap(out) ssize_t, off_t, gpgme_error_t, gpgme_err_code_t, gpgme_err_source_t, gpg_error_t {
  $result = PyLong_FromLong($1);
}
/* XXX: This is wrong at least for off_t if compiled with LFS.  */
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
    return PyErr_SetFromErrno(PyExc_RuntimeError);
  }
  $result = PyBytes_FromStringAndSize($1,result);
  free($1);
}

/* For gpgme_data_write, but should be universal.  */
%typemap(in) (const void *buffer, size_t size) {
  Py_ssize_t ssize;

  if ($input == Py_None)
    $1 = NULL, $2 = 0;
  else if (PyUnicode_Check($input))
    $1 = PyUnicode_AsUTF8AndSize($input, &ssize);
  else if (PyBytes_Check($input))
    PyBytes_AsStringAndSize($input, (char **) &$1, &ssize);
  else {
    PyErr_Format(PyExc_TypeError,
                 "arg %d: expected str, bytes, or None, got %s",
		 $argnum, $input->ob_type->tp_name);
    return NULL;
  }

  if (! $1)
    $2 = 0;
  else
    {
      assert (ssize >= 0);
      $2 = (size_t) ssize;
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
  if (! PyTuple_Check($input))
    return PyErr_Format(PyExc_TypeError, "edit callback must be a tuple");
  if (PyTuple_Size($input) != 2 && PyTuple_Size($input) != 3)
    return PyErr_Format(PyExc_TypeError,
                        "edit callback must be a tuple of size 2 or 3");

  $1 = (gpgme_edit_cb_t) pyEditCb;
  $2 = $input;
}

/* Include the unmodified <gpgme.h> for cc, and the cleaned-up local
   version for SWIG.  We do, however, want to hide certain fields on
   some structs, which we provide prior to including the version for
   SWIG.  */
%{
#include <gpgme.h>
#include "src/data.h"	/* For struct gpgme_data.  */
%}

/* This is for notations, where we want to hide the length fields, and
   the unused bit field block.  */
struct _gpgme_sig_notation
{
  struct _gpgme_sig_notation *next;

  /* If NAME is a null pointer, then VALUE contains a policy URL
     rather than a notation.  */
  char *name;

  /* The value of the notation data.  */
  char *value;

  /* The accumulated flags.  */
  gpgme_sig_notation_flags_t flags;

  /* Notation data is human-readable.  */
  unsigned int human_readable : 1;

  /* Notation data is critical.  */
  unsigned int critical : 1;
};

/* Now include our local modified version.  Any structs defined above
   are ignored.  */
%include "gpgme.h"

%include "errors.i"

// Generating and handling pointers-to-pointers.

%pointer_functions(gpgme_ctx_t, gpgme_ctx_t_p);
%pointer_functions(gpgme_data_t, gpgme_data_t_p);
%pointer_functions(gpgme_key_t, gpgme_key_t_p);
%pointer_functions(gpgme_error_t, gpgme_error_t_p);
%pointer_functions(gpgme_trust_item_t, gpgme_trust_item_t_p);
%pointer_functions(gpgme_engine_info_t, gpgme_engine_info_t_p);

// Helper functions.

%{
#include <stdio.h>
%}
FILE *fdopen(int fildes, const char *mode);

%{
#include "helpers.h"

/* SWIG support for helpers.c  */
PyObject *
pygpgme_wrap_gpgme_data_t(gpgme_data_t data)
{
  return SWIG_NewPointerObj(data, SWIGTYPE_p_gpgme_data, 0);
}

gpgme_ctx_t
pygpgme_unwrap_gpgme_ctx_t(PyObject *wrapped)
{
  gpgme_ctx_t result;
  if (SWIG_ConvertPtr(wrapped,
                      (void **) &result,
                      SWIGTYPE_p_gpgme_context,
                      SWIG_POINTER_EXCEPTION) == -1)
    return NULL;
  return result;
}
%}

%include "helpers.h"
