/* wait.h - Definitions for the wait queue interface.
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *      Copyright (C) 2001, 2002 g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef WAIT_H
#define WAIT_H

#include "gpgme.h"
#include "sema.h"

struct fd_table
{
  DECLARE_LOCK (lock);
  struct io_select_fd_s *fds;
  size_t size;
};
typedef struct fd_table *fd_table_t;

void _gpgme_fd_table_init (fd_table_t fdt);
void _gpgme_fd_table_deinit (fd_table_t fdt);

GpgmeError _gpgme_add_io_cb (void *data, int fd, int dir,
			     GpgmeIOCb fnc, void *fnc_data, void **r_tag);
void _gpgme_remove_io_cb (void *tag);
void _gpgme_wait_event_cb (void *data, GpgmeEventIO type, void *type_data);

GpgmeError _gpgme_wait_one (GpgmeCtx ctx);

#endif	/* WAIT_H */
