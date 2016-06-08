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

#include <gpgme.h>
#include "Python.h"

#ifdef _WIN32
#include <windows.h>
#define write(fd, str, sz) {DWORD written; WriteFile((HANDLE) fd, str, sz, &written, 0);}
#endif

void pygpgme_exception_init(void);
gpgme_error_t pygpgme_exception2code(void);

PyObject *object_to_gpgme_t(PyObject *input, const char *objtype, int argnum);
PyObject *object_to_gpgme_data_t(PyObject *input, int argnum,
				 gpgme_data_t *wrapper,
				 PyObject **bytesio, Py_buffer *view);

void pygpgme_clear_generic_cb(PyObject **cb);
PyObject *pygpgme_raise_callback_exception(PyObject *self);

void pygpgme_set_passphrase_cb(gpgme_ctx_t ctx, PyObject *cb,
			       PyObject **freelater);
void pygpgme_set_progress_cb(gpgme_ctx_t ctx, PyObject *cb, PyObject **freelater);
void pygpgme_set_status_cb(gpgme_ctx_t ctx, PyObject *cb,
                           PyObject **freelater);

gpgme_error_t pyEditCb(void *opaque, gpgme_status_code_t status,
		       const char *args, int fd);

gpgme_error_t pygpgme_data_new_from_cbs(gpgme_data_t *r_data,
                                        PyObject *pycbs,
                                        PyObject **freelater);

/* SWIG support for helpers.c  */
PyObject *pygpgme_wrap_gpgme_data_t(gpgme_data_t data);
