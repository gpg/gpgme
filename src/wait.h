/* wait.h - Definitions for the wait queue interface.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004. 2019 g10 Code GmbH

   This file is part of GPGME.

   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef WAIT_H
#define WAIT_H

#include "gpgme.h"
#include "sema.h"

/* A registered fd handler can be removed using the tag that
 * identifies it.  In the public API that tag is an an opaque
 * pointer. */
struct io_cb_tag_s
{
  /* The s/n of the context for which the fd was registered.  */
  uint64_t serial;

  /* The actual fd.  */
  int fd;

  /* This is used by the wrappers for the user event loop.  */
  void *user_tag;

  /* A string used describing the data.  This is used for tracing.  */
  const char *desc;
};


gpgme_error_t _gpgme_add_io_cb (void *data, int fd, int dir,
                                gpgme_io_cb_t fnc, void *fnc_data,
                                void **r_tag);
gpgme_error_t _gpgme_add_io_cb_user (void *data, int fd, int dir,
                                     gpgme_io_cb_t fnc, void *fnc_data,
                                     void **r_tag);

void _gpgme_remove_io_cb (void *tag);
void _gpgme_remove_io_cb_user (void *tag);


void _gpgme_wait_global_event_cb (void *data, gpgme_event_io_t type,
				  void *type_data);


void _gpgme_wait_private_event_cb (void *data, gpgme_event_io_t type,
				   void *type_data);
void _gpgme_wait_user_event_cb (void *data, gpgme_event_io_t type,
				void *type_data);




/* Session based interfaces require to make a distinction between IPC
   errors and operational errors.  To glue this into the old
   interface, I/O handlers (esp. the status handler) are called with a
   struct as the opaque value that contains the handlers opaque value
   but also a field for the operational error to be returned.  */
struct io_cb_data
{
  /* If this is the first field, the old internal code will still work.  */
  void *handler_value;

  /* The I/O callback can pass an operational error here.  */
  gpgme_error_t op_err;
};

#endif	/* WAIT_H */
