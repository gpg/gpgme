/* data-fd.c - A file descripor based data object.
   Copyright (C) 2002 g10 Code GmbH
 
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <sys/types.h>

#include "data.h"


static ssize_t
fd_read (gpgme_data_t dh, void *buffer, size_t size)
{
  return read (dh->data.fd, buffer, size);
}


static ssize_t
fd_write (gpgme_data_t dh, const void *buffer, size_t size)
{
  return write (dh->data.fd, buffer, size);
}


static off_t
fd_seek (gpgme_data_t dh, off_t offset, int whence)
{
  return lseek (dh->data.fd, offset, whence);
}


static struct _gpgme_data_cbs fd_cbs =
  {
    fd_read,
    fd_write,
    fd_seek,
    NULL
  };


gpgme_error_t
gpgme_data_new_from_fd (gpgme_data_t *dh, int fd)
{
  gpgme_error_t err = _gpgme_data_new (dh, &fd_cbs);
  if (err)
    return err;

  (*dh)->data.fd = fd;
  return 0;
}
