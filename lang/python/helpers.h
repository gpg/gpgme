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

#include <gpgme.h>
#include "Python.h"

/* Flag specifying whether this is an in-tree build.  */
extern int gpg_in_tree_build;

PyObject *gpg_raise_callback_exception(PyObject *self);

PyObject *gpg_set_passphrase_cb(PyObject *self, PyObject *cb);
PyObject *gpg_set_progress_cb(PyObject *self, PyObject *cb);
PyObject *gpg_set_status_cb(PyObject *self, PyObject *cb);

PyObject *gpg_data_new_from_cbs(PyObject *self, PyObject *pycbs,
				 gpgme_data_t *r_data);
