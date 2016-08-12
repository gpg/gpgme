/* data.c - An abstraction for data objects.
   Copyright (C) 2002, 2003, 2004, 2005, 2007 g10 Code GmbH

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
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <errno.h>
#include <string.h>

#include "gpgme.h"
#include "data.h"
#include "util.h"
#include "ops.h"
#include "priv-io.h"
#include "debug.h"


gpgme_error_t
_gpgme_data_new (gpgme_data_t *r_dh, struct _gpgme_data_cbs *cbs)
{
  gpgme_data_t dh;

  if (!r_dh)
    return gpg_error (GPG_ERR_INV_VALUE);

  *r_dh = NULL;
  dh = calloc (1, sizeof (*dh));
  if (!dh)
    return gpg_error_from_syserror ();

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
gpgme_ssize_t
gpgme_data_read (gpgme_data_t dh, void *buffer, size_t size)
{
  gpgme_ssize_t res;
  TRACE_BEG2 (DEBUG_DATA, "gpgme_data_read", dh,
	      "buffer=%p, size=%u", buffer, size);

  if (!dh)
    {
      gpg_err_set_errno (EINVAL);
      return TRACE_SYSRES (-1);
    }
  if (!dh->cbs->read)
    {
      gpg_err_set_errno (ENOSYS);
      return TRACE_SYSRES (-1);
    }
  do
    res = (*dh->cbs->read) (dh, buffer, size);
  while (res < 0 && errno == EINTR);

  return TRACE_SYSRES (res);
}


/* Write up to SIZE bytes from buffer BUFFER to the data object with
   the handle DH.  Return the number of characters written, or -1 on
   error.  If an error occurs, errno is set.  */
gpgme_ssize_t
gpgme_data_write (gpgme_data_t dh, const void *buffer, size_t size)
{
  gpgme_ssize_t res;
  TRACE_BEG2 (DEBUG_DATA, "gpgme_data_write", dh,
	      "buffer=%p, size=%u", buffer, size);

  if (!dh)
    {
      gpg_err_set_errno (EINVAL);
      return TRACE_SYSRES (-1);
    }
  if (!dh->cbs->write)
    {
      gpg_err_set_errno (ENOSYS);
      return TRACE_SYSRES (-1);
    }
  do
    res = (*dh->cbs->write) (dh, buffer, size);
  while (res < 0 && errno == EINTR);

  return TRACE_SYSRES (res);
}


/* Set the current position from where the next read or write starts
   in the data object with the handle DH to OFFSET, relativ to
   WHENCE.  */
gpgme_off_t
gpgme_data_seek (gpgme_data_t dh, gpgme_off_t offset, int whence)
{
  TRACE_BEG2 (DEBUG_DATA, "gpgme_data_seek", dh,
	      "offset=%lli, whence=%i", offset, whence);

  if (!dh)
    {
      gpg_err_set_errno (EINVAL);
      return TRACE_SYSRES (-1);
    }
  if (!dh->cbs->seek)
    {
      gpg_err_set_errno (ENOSYS);
      return TRACE_SYSRES (-1);
    }

  /* For relative movement, we must take into account the actual
     position of the read counter.  */
  if (whence == SEEK_CUR)
    offset -= dh->pending_len;

  offset = (*dh->cbs->seek) (dh, offset, whence);
  if (offset >= 0)
    dh->pending_len = 0;

  return TRACE_SYSRES (offset);
}


/* Release the data object with the handle DH.  */
void
gpgme_data_release (gpgme_data_t dh)
{
  TRACE (DEBUG_DATA, "gpgme_data_release", dh);

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
  TRACE1 (DEBUG_DATA, "gpgme_data_get_encoding", dh,
	  "dh->encoding=%i", dh ? dh->encoding : GPGME_DATA_ENCODING_NONE);
  return dh ? dh->encoding : GPGME_DATA_ENCODING_NONE;
}


/* Set the encoding meta information for the data object with handle
   DH to ENC.  */
gpgme_error_t
gpgme_data_set_encoding (gpgme_data_t dh, gpgme_data_encoding_t enc)
{
  TRACE_BEG1 (DEBUG_DATA, "gpgme_data_set_encoding", dh,
	      "encoding=%i", enc);
  if (!dh)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));
  if (enc < 0 || enc > GPGME_DATA_ENCODING_MIME)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));
  dh->encoding = enc;
  return TRACE_ERR (0);
}


/* Set the file name associated with the data object with handle DH to
   FILE_NAME.  */
gpgme_error_t
gpgme_data_set_file_name (gpgme_data_t dh, const char *file_name)
{
  TRACE_BEG1 (DEBUG_DATA, "gpgme_data_set_file_name", dh,
	      "file_name=%s", file_name);

  if (!dh)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (dh->file_name)
    free (dh->file_name);

  if (file_name)
    {
      dh->file_name = strdup (file_name);
      if (!dh->file_name)
	return TRACE_ERR (gpg_error_from_syserror ());
    }
  else
    dh->file_name = 0;

  return TRACE_ERR (0);
}


/* Get the file name associated with the data object with handle DH,
   or NULL if there is none.  */
char *
gpgme_data_get_file_name (gpgme_data_t dh)
{
  if (!dh)
    {
      TRACE (DEBUG_DATA, "gpgme_data_get_file_name", dh);
      return NULL;
    }

  TRACE1 (DEBUG_DATA, "gpgme_data_get_file_name", dh,
	  "dh->file_name=%s", dh->file_name);
  return dh->file_name;
}


/* Set a flag for the data object DH.  See the manual for details.  */
gpg_error_t
gpgme_data_set_flag (gpgme_data_t dh, const char *name, const char *value)
{
  TRACE_BEG2 (DEBUG_DATA, "gpgme_data_set_flag", dh,
	      "%s=%s", name, value);

  if (!dh)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (!strcmp (name, "size-hint"))
    {
      dh->size_hint= value? _gpgme_string_to_off (value) : 0;
    }
  else
    return gpg_error (GPG_ERR_UNKNOWN_NAME);

  return 0;
}



/* Functions to support the wait interface.  */

gpgme_error_t
_gpgme_data_inbound_handler (void *opaque, int fd)
{
  struct io_cb_data *data = (struct io_cb_data *) opaque;
  gpgme_data_t dh = (gpgme_data_t) data->handler_value;
  char buffer[BUFFER_SIZE];
  char *bufp = buffer;
  gpgme_ssize_t buflen;
  TRACE_BEG1 (DEBUG_CTX, "_gpgme_data_inbound_handler", dh,
	      "fd=0x%x", fd);

  buflen = _gpgme_io_read (fd, buffer, BUFFER_SIZE);
  if (buflen < 0)
    return gpg_error_from_syserror ();
  if (buflen == 0)
    {
      _gpgme_io_close (fd);
      return TRACE_ERR (0);
    }

  do
    {
      gpgme_ssize_t amt = gpgme_data_write (dh, bufp, buflen);
      if (amt == 0 || (amt < 0 && errno != EINTR))
	return TRACE_ERR (gpg_error_from_syserror ());
      bufp += amt;
      buflen -= amt;
    }
  while (buflen > 0);
  return TRACE_ERR (0);
}


gpgme_error_t
_gpgme_data_outbound_handler (void *opaque, int fd)
{
  struct io_cb_data *data = (struct io_cb_data *) opaque;
  gpgme_data_t dh = (gpgme_data_t) data->handler_value;
  gpgme_ssize_t nwritten;
  TRACE_BEG1 (DEBUG_CTX, "_gpgme_data_outbound_handler", dh,
	      "fd=0x%x", fd);

  if (!dh->pending_len)
    {
      gpgme_ssize_t amt = gpgme_data_read (dh, dh->pending, BUFFER_SIZE);
      if (amt < 0)
	return TRACE_ERR (gpg_error_from_syserror ());
      if (amt == 0)
	{
	  _gpgme_io_close (fd);
	  return TRACE_ERR (0);
	}
      dh->pending_len = amt;
    }

  nwritten = _gpgme_io_write (fd, dh->pending, dh->pending_len);
  if (nwritten == -1 && errno == EAGAIN)
    return TRACE_ERR (0);

  if (nwritten == -1 && errno == EPIPE)
    {
      /* Not much we can do.  The other end closed the pipe, but we
	 still have data.  This should only ever happen if the other
	 end is going to tell us what happened on some other channel.
	 Silently close our end.  */
      _gpgme_io_close (fd);
      return TRACE_ERR (0);
    }

  if (nwritten <= 0)
    return TRACE_ERR (gpg_error_from_syserror ());

  if (nwritten < dh->pending_len)
    memmove (dh->pending, dh->pending + nwritten, dh->pending_len - nwritten);
  dh->pending_len -= nwritten;
  return TRACE_ERR (0);
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


/* Get the size-hint value for DH or 0 if not available.  */
gpgme_off_t
_gpgme_data_get_size_hint (gpgme_data_t dh)
{
  return dh ? dh->size_hint : 0;
}
