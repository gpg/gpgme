/* data-fd.c - A file descriptor based data object.
 * Copyright (C) 2002, 2004 g10 Code GmbH
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
 * License along with this program; if not, see <https://gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include "debug.h"
#include "data.h"


static gpgme_ssize_t
fd_read (gpgme_data_t dh, void *buffer, size_t size)
{
  return read (dh->data.fd, buffer, size);
}


static gpgme_ssize_t
fd_write (gpgme_data_t dh, const void *buffer, size_t size)
{
  return write (dh->data.fd, buffer, size);
}


static gpgme_off_t
fd_seek (gpgme_data_t dh, gpgme_off_t offset, int whence)
{
  return lseek (dh->data.fd, offset, whence);
}


static int
fd_get_fd (gpgme_data_t dh)
{
  return (dh->data.fd);
}


static struct _gpgme_data_cbs fd_cbs =
  {
    fd_read,
    fd_write,
    fd_seek,
    NULL,
    fd_get_fd
  };


gpgme_error_t
gpgme_data_new_from_fd (gpgme_data_t *r_dh, int fd)
{
  gpgme_error_t err;
  TRACE_BEG  (DEBUG_DATA, "gpgme_data_new_from_fd", r_dh, "fd=%d", fd);

  err = _gpgme_data_new (r_dh, &fd_cbs);
  if (err)
    return TRACE_ERR (err);

  (*r_dh)->data.fd = fd;
  TRACE_SUC ("dh=%p", *r_dh);
  return 0;
}
