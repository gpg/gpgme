/* data-stream.c - A memory based data object.
 *      Copyright (C) 2002 g10 Code GmbH
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>

#include "data.h"


static int
stream_read (GpgmeData dh, void *buffer, size_t size)
{
  size_t amt = fread (buffer, 1, size, dh->data.stream);
  if (amt > 0)
    return amt;
  return ferror (dh->data.stream) ? -1 : 0;
}


static ssize_t
stream_write (GpgmeData dh, const void *buffer, size_t size)
{
  size_t amt = fwrite (buffer, 1, size, dh->data.stream);
  if (amt > 0)
    return amt;
  return ferror (dh->data.stream) ? -1 : 0;
}


static off_t
stream_seek (GpgmeData dh, off_t offset, int whence)
{
  return fseek (dh->data.stream, offset, whence);
}


static struct gpgme_data_cbs stream_cbs =
  {
    stream_read,
    stream_write,
    stream_seek,
    NULL
  };


GpgmeError
gpgme_data_new_from_stream (GpgmeData *dh, FILE *stream)
{
  GpgmeError err = _gpgme_data_new (dh, &stream_cbs);
  if (err)
    return err;

  (*dh)->data.stream = stream;
  return 0;
}
