/* data.c - An abstraction for data objects.
   Copyright (C) 2002, 2003, 2004, 2005 g10 Code GmbH

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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "gpgme.h"
#include "data.h"
#include "util.h"
#include "ops.h"
#include "priv-io.h"


gpgme_error_t
_gpgme_data_new (gpgme_data_t *r_dh, struct _gpgme_data_cbs *cbs)
{
  gpgme_data_t dh;

  if (!r_dh)
    return gpg_error (GPG_ERR_INV_VALUE);

  *r_dh = NULL;
  dh = calloc (1, sizeof (*dh));
  if (!dh)
    return gpg_error_from_errno (errno);

  dh->cbs = cbs;

  *r_dh = dh;
  return 0;
}


void
_gpgme_data_release (gpgme_data_t dh)
{
  if (!dh)
    return;

  if (dh->file_name)
    free (dh->file_name);
  free (dh);
}


/* Read up to SIZE bytes into buffer BUFFER from the data object with
   the handle DH.  Return the number of characters read, 0 on EOF and
   -1 on error.  If an error occurs, errno is set.  */
ssize_t
gpgme_data_read (gpgme_data_t dh, void *buffer, size_t size)
{
  if (!dh)
    {
      errno = EINVAL;
      return -1;
    }
  if (!dh->cbs->read)
    {
      errno = ENOSYS;
      return -1;
    }
  return (*dh->cbs->read) (dh, buffer, size);
}


/* Write up to SIZE bytes from buffer BUFFER to the data object with
   the handle DH.  Return the number of characters written, or -1 on
   error.  If an error occurs, errno is set.  */
ssize_t
gpgme_data_write (gpgme_data_t dh, const void *buffer, size_t size)
{
  if (!dh)
    {
      errno = EINVAL;
      return -1;
    }
  if (!dh->cbs->write)
    {
      errno = ENOSYS;
      return -1;
    }
  return (*dh->cbs->write) (dh, buffer, size);
}


/* Set the current position from where the next read or write starts
   in the data object with the handle DH to OFFSET, relativ to
   WHENCE.  */
off_t
gpgme_data_seek (gpgme_data_t dh, off_t offset, int whence)
{
  if (!dh)
    {
      errno = EINVAL;
      return -1;
    }
  if (!dh->cbs->seek)
    {
      errno = ENOSYS;
      return -1;
    }

  /* For relative movement, we must take into account the actual
     position of the read counter.  */
  if (whence == SEEK_CUR)
    offset -= dh->pending_len;

  offset = (*dh->cbs->seek) (dh, offset, whence);
  if (offset >= 0)
    dh->pending_len = 0;

  return offset;
}


/* Release the data object with the handle DH.  */
void
gpgme_data_release (gpgme_data_t dh)
{
  if (!dh)
    return;

  if (dh->cbs->release)
    (*dh->cbs->release) (dh);
  _gpgme_data_release (dh);
}


/* Get the current encoding meta information for the data object with
   handle DH.  */
gpgme_data_encoding_t
gpgme_data_get_encoding (gpgme_data_t dh)
{
  return dh ? dh->encoding : GPGME_DATA_ENCODING_NONE;
}


/* Set the encoding meta information for the data object with handle
   DH to ENC.  */
gpgme_error_t
gpgme_data_set_encoding (gpgme_data_t dh, gpgme_data_encoding_t enc)
{
  if (!dh)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (enc < 0 || enc > GPGME_DATA_ENCODING_ARMOR)
    return gpg_error (GPG_ERR_INV_VALUE);
  dh->encoding = enc;
  return 0;
}


/* Set the file name associated with the data object with handle DH to
   FILE_NAME.  */
gpgme_error_t
gpgme_data_set_file_name (gpgme_data_t dh, const char *file_name)
{
  if (!dh)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (dh->file_name)
    free (dh->file_name);

  if (file_name)
    {
      dh->file_name = strdup (file_name);
      if (!dh->file_name)
	return gpg_error_from_errno (errno);
    }
  else
    dh->file_name = 0;

  return 0;
}

/* Get the file name associated with the data object with handle DH,
   or NULL if there is none.  */
char *
gpgme_data_get_file_name (gpgme_data_t dh)
{
  if (!dh)
    return NULL;

  return dh->file_name;
}


/* Functions to support the wait interface.  */

gpgme_error_t
_gpgme_data_inbound_handler (void *opaque, int fd)
{
  gpgme_data_t dh = (gpgme_data_t) opaque;
  char buffer[BUFFER_SIZE];
  char *bufp = buffer;
  ssize_t buflen;

  buflen = _gpgme_io_read (fd, buffer, BUFFER_SIZE);
  if (buflen < 0)
    return gpg_error_from_errno (errno);
  if (buflen == 0)
    {
      _gpgme_io_close (fd);
      return 0;
    }

  do
    {
      ssize_t amt = gpgme_data_write (dh, bufp, buflen);
      if (amt == 0 || (amt < 0 && errno != EINTR))
	return gpg_error_from_errno (errno);
      bufp += amt;
      buflen -= amt;
    }
  while (buflen > 0);
  return 0;
}


gpgme_error_t
_gpgme_data_outbound_handler (void *opaque, int fd)
{
  gpgme_data_t dh = (gpgme_data_t) opaque;
  ssize_t nwritten;

  if (!dh->pending_len)
    {
      ssize_t amt = gpgme_data_read (dh, dh->pending, BUFFER_SIZE);
      if (amt < 0)
	return gpg_error_from_errno (errno);
      if (amt == 0)
	{
	  _gpgme_io_close (fd);
	  return 0;
	}
      dh->pending_len = amt;
    }

  nwritten = _gpgme_io_write (fd, dh->pending, dh->pending_len);
  if (nwritten == -1 && errno == EAGAIN)
    return 0;

  if (nwritten == -1 && errno == EPIPE)
    {
      /* Not much we can do.  The other end closed the pipe, but we
	 still have data.  This should only ever happen if the other
	 end is going to tell us what happened on some other channel.
	 Silently close our end.  */
      _gpgme_io_close (fd);
      return 0;
    }

  if (nwritten <= 0)
    return gpg_error_from_errno (errno);

  if (nwritten < dh->pending_len)
    memmove (dh->pending, dh->pending + nwritten, dh->pending_len - nwritten);
  dh->pending_len -= nwritten;
  return 0;
}


/* Get the file descriptor associated with DH, if possible.  Otherwise
   return -1.  */
int
_gpgme_data_get_fd (gpgme_data_t dh)
{
  if (!dh || !dh->cbs->get_fd)
    return -1;
  return (*dh->cbs->get_fd) (dh);
}
