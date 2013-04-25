/* data-user.c - A user callback based data object.
   Copyright (C) 2002, 2004 g10 Code GmbH

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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <errno.h>

#include "debug.h"
#include "data.h"


static gpgme_ssize_t
user_read (gpgme_data_t dh, void *buffer, size_t size)
{
  if (!dh->data.user.cbs->read)
    {
      gpg_err_set_errno (EBADF);
      return -1;
    }

  return (*dh->data.user.cbs->read) (dh->data.user.handle, buffer, size);
}


static gpgme_ssize_t
user_write (gpgme_data_t dh, const void *buffer, size_t size)
{
  if (!dh->data.user.cbs->write)
    {
      gpg_err_set_errno (EBADF);
      return -1;
    }

  return (*dh->data.user.cbs->write) (dh->data.user.handle, buffer, size);
}


static gpgme_off_t
user_seek (gpgme_data_t dh, gpgme_off_t offset, int whence)
{
  if (!dh->data.user.cbs->seek)
    {
      gpg_err_set_errno (EBADF);
      return -1;
    }

  return (*dh->data.user.cbs->seek) (dh->data.user.handle, offset, whence);
}


static void
user_release (gpgme_data_t dh)
{
  if (dh->data.user.cbs->release)
    (*dh->data.user.cbs->release) (dh->data.user.handle);
}


static struct _gpgme_data_cbs user_cbs =
  {
    user_read,
    user_write,
    user_seek,
    user_release,
    NULL
  };


gpgme_error_t
gpgme_data_new_from_cbs (gpgme_data_t *r_dh, gpgme_data_cbs_t cbs, void *handle)
{
  gpgme_error_t err;
  TRACE_BEG1 (DEBUG_DATA, "gpgme_data_new_from_cbs", r_dh, "handle=%p", handle);

  err = _gpgme_data_new (r_dh, &user_cbs);
  if (err)
    return TRACE_ERR (err);

  (*r_dh)->data.user.cbs = cbs;
  (*r_dh)->data.user.handle = handle;
  return TRACE_SUC1 ("dh=%p", *r_dh);
}
