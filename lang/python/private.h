/*
 * Copyright (C) 2016 g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <gpgme.h>

#ifndef _GPG_PRIVATE_H_
#define _GPG_PRIVATE_H_

/* GPGME glue.  Implemented in helpers.c.  */

void _gpg_exception_init(void);
gpgme_error_t _gpg_exception2code(void);

PyObject *_gpg_obj2gpgme_t(PyObject *input, const char *objtype, int argnum);
PyObject *_gpg_obj2gpgme_data_t(PyObject *input, int argnum,
				 gpgme_data_t *wrapper,
				 PyObject **bytesio, Py_buffer *view);

PyObject *_gpg_wrap_result(PyObject *fragile, const char *classname);

gpgme_error_t _gpg_interact_cb(void *opaque, const char *keyword,
				const char *args, int fd);
gpgme_error_t _gpg_assuan_data_cb (void *hook,
				    const void *data, size_t datalen);
gpgme_error_t _gpg_assuan_inquire_cb (void *hook,
				       const char *name, const char *args,
				       gpgme_data_t *r_data);
gpgme_error_t _gpg_assuan_status_cb (void *hook,
				      const char *status, const char *args);



/* SWIG runtime support.  Implemented in gpgme.i.  */

PyObject *_gpg_wrap_gpgme_data_t(gpgme_data_t data);
gpgme_ctx_t _gpg_unwrap_gpgme_ctx_t(PyObject *wrapped);

#endif /* _GPG_PRIVATE_H_ */
