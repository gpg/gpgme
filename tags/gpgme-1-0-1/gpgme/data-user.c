/* data-user.c - A user callback based data object.
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

#include <sys/types.h>

#include "data.h"


static ssize_t
user_read (gpgme_data_t dh, void *buffer, size_t size)
{
  return (*dh->data.user.cbs->read) (dh->data.user.handle, buffer, size);
}


static ssize_t
user_write (gpgme_data_t dh, const void *buffer, size_t size)
{
  return (*dh->data.user.cbs->write) (dh->data.user.handle, buffer, size);
}


static off_t
user_seek (gpgme_data_t dh, off_t offset, int whence)
{
  return (*dh->data.user.cbs->seek) (dh->data.user.handle, offset, whence);
}


static void
user_release (gpgme_data_t dh)
{
  (*dh->data.user.cbs->release) (dh->data.user.handle);
}


static struct _gpgme_data_cbs user_cbs =
  {
    user_read,
    user_write,
    user_seek,
    user_release
  };


gpgme_error_t
gpgme_data_new_from_cbs (gpgme_data_t *dh, gpgme_data_cbs_t cbs, void *handle)
{
  gpgme_error_t err = _gpgme_data_new (dh, &user_cbs);
  if (err)
    return err;

  (*dh)->data.user.cbs = cbs;
  (*dh)->data.user.handle = handle;
  return 0;
}
