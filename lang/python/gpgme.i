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
%module gpgme
%include "cpointer.i"
%include "cstring.i"

/* no need to record whether GPGME's c++ bindings were built
   concurrently with the python bindings */
%ignore HAVE_CXX11;

%{
/* We use public symbols (e.g. "_obsolete_class") which are marked as
 * deprecated but we need to keep them.  Silence the warning.  */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
%}

/* Generate doc strings for all methods.

   This will generate docstrings of the form

     gpgme_op_encrypt(ctx, recp, flags, plain, cipher) -> gpgme_error_t

   which we transform into

     ctx.op_encrypt(recp, flags, plain, cipher) -> gpgme_error_t

   for automagically wrapped functions.  */
%feature("autodoc", "0");


/* Allow use of Unicode objects, bytes, and None for strings.  */
%typemap(in) const char *(PyObject *encodedInput = NULL) {
  if ($input == Py_None)
    $1 = NULL;
  else if (PyUnicode_Check($input))
    {
      encodedInput = PyUnicode_AsUTF8String($input);
      if (encodedInput == NULL)
        return NULL;
      $1 = PyBytes_AsString(encodedInput);
    }
  else if (PyBytes_Check($input))
    $1 = PyBytes_AsString($input);
  else {
    PyErr_Format(PyExc_TypeError,
                 "arg %d: expected str, bytes, or None, got %s",
		 $argnum, $input->ob_type->tp_name);
    return NULL;
  }
}
%typemap(freearg) const char * {
  Py_XDECREF(encodedInput$argnum);
}

/* Likewise for a list of strings.  */
%typemap(in) const char *[] (void *vector = NULL,
                             size_t size,
                             PyObject **pyVector = NULL) {
  /* Check if is a list */
  if (PyList_Check($input)) {
    size_t i, j;
    size = PyList_Size($input);
    $1 = (char **) (vector = malloc((size+1) * sizeof(char *)));
    pyVector = calloc(sizeof *pyVector, size);

    for (i = 0; i < size; i++) {
      PyObject *o = PyList_GetItem($input,i);
      if (PyUnicode_Check(o))
        {
          pyVector[i] = PyUnicode_AsUTF8String(o);
          if (pyVector[i] == NULL)
            {
              free(vector);
              for (j = 0; j < i; j++)
                Py_XDECREF(pyVector[j]);
              return NULL;
            }
          $1[i] = PyBytes_AsString(pyVector[i]);
        }
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
  size_t i;
  free(vector$argnum);
  for (i = 0; i < size$argnum; i++)
    Py_XDECREF(pyVector$argnum[i]);
}

/* Release returned buffers as necessary.  */
%typemap(newfree) char * "gpgme_free($1);";
%newobject gpgme_data_release_and_get_mem;
%newobject gpgme_pubkey_algo_string;
%newobject gpgme_addrspec_from_uid;

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

      /* Following code is from swig's python.swg.  */
      if ((SWIG_ConvertPtr(pypointer,(void **) &$1[i], $*1_descriptor,SWIG_POINTER_EXCEPTION | $disown )) == -1) {
        Py_DECREF(pypointer);
	PyErr_Format(PyExc_TypeError,
                     "arg %d: list must contain only gpgme_key_ts, got %s "
                     "at position %d",
                     $argnum, pypointer->ob_type->tp_name, i);
        free($1);
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

/* Special handling for references to our objects.  */
%typemap(in) gpgme_data_t DATAIN (gpgme_data_t wrapper = NULL,
                                  PyObject *bytesio = NULL,
                                  Py_buffer view, int have_view = 0) {
  /* If we create a temporary wrapper object, we will store it in
     wrapperN, where N is $argnum.  Here in this fragment, SWIG will
     automatically append $argnum.  */
  memset(&view, 0, sizeof view);
  if ($input == Py_None)
    $1 = NULL;
  else {
    PyObject *pypointer;
    pypointer = _gpg_obj2gpgme_data_t($input, $argnum, &wrapper,
                                       &bytesio, &view);
    if (pypointer == NULL)
      return NULL;
    have_view = !! view.obj;

    /* input = $input, 1 = $1, 1_descriptor = $1_descriptor */

    /* Following code is from swig's python.swg.  */

    if ((SWIG_ConvertPtr(pypointer,(void **) &$1, $1_descriptor,
         SWIG_POINTER_EXCEPTION | $disown )) == -1) {
      Py_DECREF(pypointer);
      return NULL;
    }
    Py_DECREF(pypointer);
  }
}

#if HAVE_DATA_H
/* If we are doing an in-tree build, we can use the internal
   representation of struct gpgme_data for an very efficient check if
   the buffer has been modified.  */
%{
#include "data.h"	/* For struct gpgme_data.  */
%}
#endif

%typemap(freearg) gpgme_data_t DATAIN {
  /* See whether we need to update the Python buffer.  */
  if (resultobj && wrapper$argnum && view$argnum.buf)
    {
      int dirty;
      char *new_data = NULL;
      size_t new_size;

#if HAVE_DATA_H
      new_data = wrapper$argnum->data.mem.buffer;
      new_size = wrapper$argnum->data.mem.length;
      dirty = new_data != NULL;
#else
      new_data = gpgme_data_release_and_get_mem (wrapper$argnum, &new_size);
      wrapper$argnum = NULL;
      dirty = new_size != view$argnum.len
        || memcmp (new_data, view$argnum.buf, view$argnum.len);
#endif

      if (dirty)
        {
          /* The buffer is dirty.  */
          if (view$argnum.readonly)
            {
              Py_XDECREF(resultobj);
              resultobj = NULL;
              PyErr_SetString(PyExc_ValueError,
                              "cannot update read-only buffer");
            }

          /* See if we need to truncate the buffer.  */
          if (resultobj && view$argnum.len != new_size)
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
                  assert(view$argnum.obj == NULL);
                  retval = PyObject_CallMethod(bytesio$argnum, "truncate",
                                               "l", (long) new_size);
                  if (retval == NULL)
                    {
                      Py_XDECREF(resultobj);
                      resultobj = NULL;
                    }
                  else
                    {
                      Py_DECREF(retval);

                      retval = PyObject_CallMethod(bytesio$argnum,
                                                   "getbuffer", NULL);
                      if (retval == NULL
                          || PyObject_GetBuffer(retval, &view$argnum,
                                           PyBUF_SIMPLE|PyBUF_WRITABLE) < 0)
                        {
                          Py_XDECREF(resultobj);
                          resultobj = NULL;
                        }

                      Py_XDECREF(retval);

                      if (resultobj && view$argnum.len
                          != new_size)
                        {
                          Py_XDECREF(resultobj);
                          resultobj = NULL;
                          PyErr_Format(PyExc_ValueError,
                                       "Expected buffer of length %zu, got %zi",
                                       new_size,
                                       view$argnum.len);
                        }
                    }
                }
            }
          if (resultobj)
            memcpy(view$argnum.buf, new_data, new_size);
        }
#if ! HAVE_DATA_H
      free (new_data);
#endif
    }

  /* Free the temporary wrapper, if any.  */
  if (wrapper$argnum)
    gpgme_data_release(wrapper$argnum);
  Py_XDECREF (bytesio$argnum);
  if (have_view$argnum && view$argnum.buf)
    PyBuffer_Release(&view$argnum);
}

%apply gpgme_data_t DATAIN {gpgme_data_t plain, gpgme_data_t cipher,
			gpgme_data_t sig, gpgme_data_t signed_text,
			gpgme_data_t plaintext, gpgme_data_t keydata,
			gpgme_data_t pubkey, gpgme_data_t seckey,
			gpgme_data_t out, gpgme_data_t data};

/* SWIG has problems interpreting ssize_t, off_t or gpgme_error_t in
   gpgme.h.  */
%typemap(out) ssize_t, gpgme_error_t, gpgme_err_code_t, gpgme_err_source_t, gpg_error_t {
  $result = PyLong_FromLong($1);
}

%typemap(in) ssize_t, gpgme_error_t, gpgme_err_code_t, gpgme_err_source_t, gpg_error_t {
  if (PyLong_Check($input))
    $1 = PyLong_AsLong($input);
#if PY_MAJOR_VERSION < 3
  else if (PyInt_Check($input))
    $1 = PyInt_AsLong($input);
#endif
  else
    PyErr_SetString(PyExc_TypeError, "Numeric argument expected");
}

%typemap(out) off_t {
#if _FILE_OFFSET_BITS == 64
  $result = PyLong_FromLongLong($1);
#else
  $result = PyLong_FromLong($1);
#endif
}

%typemap(in) off_t {
  if (PyLong_Check($input))
#if _FILE_OFFSET_BITS == 64
    $1 = PyLong_AsLongLong($input);
#else
    $1 = PyLong_AsLong($input);
#endif
#if PY_MAJOR_VERSION < 3
  else if (PyInt_Check($input))
    $1 = PyInt_AsLong($input);
#endif
  else
    PyErr_SetString(PyExc_TypeError, "Numeric argument expected");
}

/* Those are for gpgme_data_read() and gpgme_strerror_r().  */
%typemap(in) (void *buffer, size_t size), (char *buf, size_t buflen) {
  {
    long tmp$argnum;
    if (PyLong_Check($input))
      tmp$argnum = PyLong_AsLong($input);
#if PY_MAJOR_VERSION < 3
    else if (PyInt_Check($input))
      tmp$argnum = PyInt_AsLong($input);
#endif
    else
      {
        PyErr_SetString(PyExc_TypeError, "Numeric argument expected");
        return NULL;
      }

    if (tmp$argnum < 0) {
      PyErr_SetString(PyExc_ValueError, "Positive integer expected");
      return NULL;
    }
    $2 = (size_t) tmp$argnum;
    $1 = ($1_ltype) malloc($2+1);
  }
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
%typemap(in) (const void *buffer, size_t size)(PyObject *encodedInput = NULL) {
  Py_ssize_t ssize;

  if ($input == Py_None)
    $1 = NULL, $2 = 0;
  else if (PyUnicode_Check($input))
    {
      encodedInput = PyUnicode_AsUTF8String($input);
      if (encodedInput == NULL)
        return NULL;
      if (PyBytes_AsStringAndSize(encodedInput, (char **) &$1, &ssize) == -1)
        {
          Py_DECREF(encodedInput);
          return NULL;
        }
    }
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
%typemap(freearg) (const void *buffer, size_t size) {
  Py_XDECREF(encodedInput$argnum);
}

/* Make types containing 'next' field to be lists.  */
%ignore next;
%typemap(out) gpgme_sig_notation_t, gpgme_subkey_t,
   gpgme_key_sig_t, gpgme_user_id_t, gpgme_invalid_key_t,
   gpgme_recipient_t, gpgme_new_signature_t, gpgme_signature_t,
   gpgme_import_status_t, gpgme_conf_arg_t, gpgme_conf_opt_t,
   gpgme_conf_comp_t, gpgme_tofu_info_t {
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



/* Wrap the fragile result objects into robust Python ones.  */
%define wrapresult(cls, name)
%typemap(out) cls {
  PyObject *fragile;
  fragile = SWIG_NewPointerObj(SWIG_as_voidptr($1), $1_descriptor,
                               %newpointer_flags);
  $result = _gpg_wrap_result(fragile, name);
  Py_DECREF(fragile);
}
%enddef

wrapresult(gpgme_encrypt_result_t, "EncryptResult")
wrapresult(gpgme_decrypt_result_t, "DecryptResult")
wrapresult(gpgme_sign_result_t, "SignResult")
wrapresult(gpgme_verify_result_t, "VerifyResult")
wrapresult(gpgme_import_result_t, "ImportResult")
wrapresult(gpgme_genkey_result_t, "GenkeyResult")
wrapresult(gpgme_keylist_result_t, "KeylistResult")
wrapresult(gpgme_vfs_mount_result_t, "VFSMountResult")

%typemap(out) gpgme_engine_info_t {
  int i;
  int size = 0;
  $1_ltype curr;
  for (curr = $1; curr != NULL; curr = curr->next) {
    size++;
  }
  $result = PyList_New(size);
  if ($result == NULL)
    return NULL;	/* raise */
  for (i=0,curr=$1; i<size; i++,curr=curr->next) {
    PyObject *fragile, *o;
    fragile = SWIG_NewPointerObj(SWIG_as_voidptr(curr), $1_descriptor,
                                 %newpointer_flags);
    if (fragile == NULL)
      {
        Py_DECREF($result);
        return NULL;	/* raise */
      }
    o = _gpg_wrap_result(fragile, "EngineInfo");
    Py_DECREF(fragile);
    if (o == NULL)
      {
        Py_DECREF($result);
        return NULL;	/* raise */
      }
    PyList_SetItem($result, i, o);
  }
}



/* Include mapper for interact callbacks.  */
%typemap(in) (gpgme_interact_cb_t fnc, void *fnc_value) {
  if (! PyTuple_Check($input))
    return PyErr_Format(PyExc_TypeError, "interact callback must be a tuple");
  if (PyTuple_Size($input) != 2 && PyTuple_Size($input) != 3)
    return PyErr_Format(PyExc_TypeError,
                        "interact callback must be a tuple of size 2 or 3");

  $1 = (gpgme_interact_cb_t) _gpg_interact_cb;
  $2 = $input;
}



/* The assuan protocol callbacks.  */
%typemap(in) (gpgme_assuan_data_cb_t data_cb, void *data_cb_value) {
  if ($input == Py_None)
    $1 = $2 = NULL;
  else
    {
      if (! PyTuple_Check($input))
        return PyErr_Format(PyExc_TypeError, "callback must be a tuple");
      if (PyTuple_Size($input) != 2)
        return PyErr_Format(PyExc_TypeError,
                            "callback must be a tuple of size 2");
      if (! PyCallable_Check(PyTuple_GetItem($input, 1)))
        return PyErr_Format(PyExc_TypeError, "second item must be callable");
      $1 = _gpg_assuan_data_cb;
      $2 = $input;
    }
}

%typemap(in) (gpgme_assuan_inquire_cb_t inq_cb, void *inq_cb_value) {
  if ($input == Py_None)
    $1 = $2 = NULL;
  else
    {
      if (! PyTuple_Check($input))
        return PyErr_Format(PyExc_TypeError, "callback must be a tuple");
      if (PyTuple_Size($input) != 2)
        return PyErr_Format(PyExc_TypeError,
                            "callback must be a tuple of size 2");
      if (! PyCallable_Check(PyTuple_GetItem($input, 1)))
        return PyErr_Format(PyExc_TypeError, "second item must be callable");
      $1 = _gpg_assuan_inquire_cb;
      $2 = $input;
    }
}

%typemap(in) (gpgme_assuan_status_cb_t stat_cb, void *stat_cb_value) {
  if ($input == Py_None)
    $1 = $2 = NULL;
  else
    {
      if (! PyTuple_Check($input))
        return PyErr_Format(PyExc_TypeError, "callback must be a tuple");
      if (PyTuple_Size($input) != 2)
        return PyErr_Format(PyExc_TypeError,
                            "callback must be a tuple of size 2");
      if (! PyCallable_Check(PyTuple_GetItem($input, 1)))
        return PyErr_Format(PyExc_TypeError, "second item must be callable");
      $1 = _gpg_assuan_status_cb;
      $2 = $input;
    }
}


/* With SWIG, you can define default arguments for parameters.
 * While it's legal in C++ it is not in C, so we cannot change the
 * already existing gpgme.h. We need, however, to declare the function
 * *before* SWIG loads it from gpgme.h. Hence, we define it here.     */
gpgme_error_t gpgme_op_keylist_start (gpgme_ctx_t ctx,
                      const char *pattern="",
                      int secret_only=0);

/* The whence argument is surprising in Python-land,
   because BytesIO or StringIO objects do not require it.
   It defaults to SEEK_SET. Let's do that for Data objects, too */
off_t gpgme_data_seek (gpgme_data_t dh, off_t offset, int whence=SEEK_SET);

/* Include the unmodified <gpgme.h> for cc, and the cleaned-up local
   version for SWIG.  We do, however, want to hide certain fields on
   some structs, which we provide prior to including the version for
   SWIG.  */
%{
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gpgme.h>
%}

/* This is for notations, where we want to hide the length fields, and
 * the unused bit field block.  We silence the warning.  */
%warnfilter(302) _gpgme_sig_notation;
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
#ifdef HAVE_CONFIG_H
%include "config.h"
#endif

%include "gpgme.h"

%include "errors.i"

/* Generating and handling pointers-to-pointers.  */

%pointer_functions(gpgme_ctx_t, gpgme_ctx_t_p);
%pointer_functions(gpgme_data_t, gpgme_data_t_p);
%pointer_functions(gpgme_key_t, gpgme_key_t_p);
%pointer_functions(gpgme_error_t, gpgme_error_t_p);
%pointer_functions(gpgme_trust_item_t, gpgme_trust_item_t_p);
%pointer_functions(gpgme_engine_info_t, gpgme_engine_info_t_p);

/* Helper functions.  */

%{
#include <stdio.h>
%}
FILE *fdopen(int fildes, const char *mode);

/* We include both headers in the generated c code...  */
%{
#include "helpers.h"
#include "private.h"

/* SWIG runtime support for helpers.c  */
PyObject *
_gpg_wrap_gpgme_data_t(gpgme_data_t data)
{
  /*
   * If SWIG is invoked without -builtin, the macro SWIG_NewPointerObj
   * expects a variable named "self".
   *
   * XXX: It is not quite clear why passing NULL as self is okay, but
   * it works with -builtin, and it seems to work just fine without
   * it too.
   */
  PyObject* self = NULL;
  (void) self;
  return SWIG_NewPointerObj(data, SWIGTYPE_p_gpgme_data, 0);
}

gpgme_ctx_t
_gpg_unwrap_gpgme_ctx_t(PyObject *wrapped)
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

/* ... but only the public definitions here.  They will be exposed to
   the Python world, so let's be careful.  */
%include "helpers.h"


%define genericrepr(cls)
%pythoncode %{
    def __repr__(self):
        names = [name for name in dir(self)
            if not name.startswith("_") and name != "this"]
        props = ", ".join(("{}={!r}".format(name, getattr(self, name))
            for name in names)
        )
        return "cls({})".format(props)
%}

%enddef

%extend _gpgme_key {
  genericrepr(Key)
};


%extend _gpgme_subkey {
  genericrepr(SubKey)
};

%extend _gpgme_key_sig {
  genericrepr(KeySig)
};

%extend _gpgme_user_id {
  genericrepr(UID)
};

%extend _gpgme_tofu_info {
  genericrepr(TofuInfo)
};
