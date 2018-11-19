/* data-stream.c - A stream based data object.
 * Copyright (C) 2002, 2004, 2018 g10 Code GmbH
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
 * License along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1+
 */

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
stream_es_read (gpgme_data_t dh, void *buffer, size_t size)
{
  size_t amt = gpgrt_fread (buffer, 1, size, dh->data.e_stream);
  if (amt > 0)
    return amt;
  return gpgrt_ferror (dh->data.e_stream) ? -1 : 0;
}


static gpgme_ssize_t
stream_es_write (gpgme_data_t dh, const void *buffer, size_t size)
{
  size_t amt = gpgrt_fwrite (buffer, 1, size, dh->data.e_stream);
  if (amt > 0)
    return amt;
  return gpgrt_ferror (dh->data.e_stream) ? -1 : 0;
}


static gpgme_off_t
stream_es_seek (gpgme_data_t dh, gpgme_off_t offset, int whence)
{
  int err;

  err = gpgrt_fseeko (dh->data.e_stream, offset, whence);
  if (err)
    return -1;

  return gpgrt_ftello (dh->data.e_stream);
}


static int
stream_es_get_fd (gpgme_data_t dh)
{
  gpgrt_fflush (dh->data.e_stream);
  return gpgrt_fileno (dh->data.e_stream);
}


static struct _gpgme_data_cbs stream_es_cbs =
  {
    stream_es_read,
    stream_es_write,
    stream_es_seek,
    NULL,
    stream_es_get_fd
  };



gpgme_error_t
gpgme_data_new_from_estream (gpgme_data_t *r_dh, gpgrt_stream_t stream)
{
  gpgme_error_t err;
  TRACE_BEG  (DEBUG_DATA, "gpgme_data_new_from_estream", r_dh, "estream=%p",
	      stream);

  err = _gpgme_data_new (r_dh, &stream_es_cbs);
  if (err)
    return TRACE_ERR (err);

  (*r_dh)->data.e_stream = stream;
  TRACE_SUC ("dh=%p", *r_dh);
  return 0;
}
