/* data-stream.c - A stream based data object.
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

#include <stdio.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include "debug.h"
#include "data.h"


static gpgme_ssize_t
stream_read (gpgme_data_t dh, void *buffer, size_t size)
{
  size_t amt = fread (buffer, 1, size, dh->data.stream);
  if (amt > 0)
    return amt;
  return ferror (dh->data.stream) ? -1 : 0;
}


static gpgme_ssize_t
stream_write (gpgme_data_t dh, const void *buffer, size_t size)
{
  size_t amt = fwrite (buffer, 1, size, dh->data.stream);
  if (amt > 0)
    return amt;
  return ferror (dh->data.stream) ? -1 : 0;
}


static gpgme_off_t
stream_seek (gpgme_data_t dh, gpgme_off_t offset, int whence)
{
  int err;

#ifdef HAVE_FSEEKO
  err = fseeko (dh->data.stream, offset, whence);
#else
  /* FIXME: Check for overflow, or at least bail at compilation.  */
  err = fseek (dh->data.stream, offset, whence);
#endif

  if (err)
    return -1;

#ifdef HAVE_FSEEKO
  return ftello (dh->data.stream);
#else
  return ftell (dh->data.stream);
#endif
}


static int
stream_get_fd (gpgme_data_t dh)
{
  fflush (dh->data.stream);
  return fileno (dh->data.stream);
}


static struct _gpgme_data_cbs stream_cbs =
  {
    stream_read,
    stream_write,
    stream_seek,
    NULL,
    stream_get_fd
  };


gpgme_error_t
gpgme_data_new_from_stream (gpgme_data_t *r_dh, FILE *stream)
{
  gpgme_error_t err;
  TRACE_BEG1 (DEBUG_DATA, "gpgme_data_new_from_stream", r_dh, "stream=%p",
	      stream);

  err = _gpgme_data_new (r_dh, &stream_cbs);
  if (err)
    return TRACE_ERR (err);

  (*r_dh)->data.stream = stream;
  return TRACE_SUC1 ("dh=%p", *r_dh);
}
