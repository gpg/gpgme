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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <gpgme.h>

#ifndef _PYME_PRIVATE_H_
#define _PYME_PRIVATE_H_

void pygpgme_exception_init(void);
gpgme_error_t pygpgme_exception2code(void);

PyObject *object_to_gpgme_t(PyObject *input, const char *objtype, int argnum);
PyObject *object_to_gpgme_data_t(PyObject *input, int argnum,
				 gpgme_data_t *wrapper,
				 PyObject **bytesio, Py_buffer *view);

PyObject *pygpgme_wrap_fragile_result(PyObject *fragile, const char *classname);

gpgme_error_t pyEditCb(void *opaque, gpgme_status_code_t status,
		       const char *args, int fd);

#endif /* _PYME_PRIVATE_H_ */
