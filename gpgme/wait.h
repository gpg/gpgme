/* wait.h - Definitions for the wait queue interface.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003 g10 Code GmbH
 
   This file is part of GPGME.
 
   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with GPGME; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifndef WAIT_H
#define WAIT_H

#include "gpgme.h"
#include "sema.h"

struct fd_table
{
  struct io_select_fd_s *fds;
  size_t size;
};
typedef struct fd_table *fd_table_t;

/* Wait items are hooked into the io_select_fd_s to connect an fd with
   a callback handler.  */
struct wait_item_s
{
  gpgme_ctx_t ctx;
  gpgme_io_cb_t handler;
  void *handler_value;
  int dir;
};

/* A registered fd handler is removed later using the tag that
   identifies it.  */
struct tag
{
  /* The context for which the fd was registered.  */
  gpgme_ctx_t ctx;

  /* The index into the fd table for this context.  */
  int idx;

  /* This is used by the wrappers for the user event loop.  */
  void *user_tag;
};


void _gpgme_fd_table_init (fd_table_t fdt);
void _gpgme_fd_table_deinit (fd_table_t fdt);

gpgme_error_t _gpgme_add_io_cb (void *data, int fd, int dir,
			     gpgme_io_cb_t fnc, void *fnc_data, void **r_tag);
void _gpgme_remove_io_cb (void *tag);
void _gpgme_wait_private_event_cb (void *data, gpgme_event_io_t type,
				   void *type_data);
void _gpgme_wait_global_event_cb (void *data, gpgme_event_io_t type,
				  void *type_data);

gpgme_error_t _gpgme_wait_user_add_io_cb (void *data, int fd, int dir,
					  gpgme_io_cb_t fnc, void *fnc_data,
					  void **r_tag);
void _gpgme_wait_user_remove_io_cb (void *tag);
void _gpgme_wait_user_event_cb (void *data, gpgme_event_io_t type,
				void *type_data);

gpgme_error_t _gpgme_wait_one (gpgme_ctx_t ctx);

#endif	/* WAIT_H */
