/* data-mem.c - A memory based data object.
 * Copyright (C) 2002, 2003, 2004, 2007 g10 Code GmbH
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

#include <errno.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <assert.h>
#include <string.h>

#include "data.h"
#include "util.h"
#include "debug.h"


static gpgme_ssize_t
mem_read (gpgme_data_t dh, void *buffer, size_t size)
{
  size_t amt = dh->data.mem.length - dh->data.mem.offset;
  const char *src;

  if (!amt)
    return 0;

  if (size < amt)
    amt = size;

  src = dh->data.mem.buffer ? dh->data.mem.buffer : dh->data.mem.orig_buffer;
  memcpy (buffer, src + dh->data.mem.offset, amt);
  dh->data.mem.offset += amt;
  return amt;
}


static gpgme_ssize_t
mem_write (gpgme_data_t dh, const void *buffer, size_t size)
{
  size_t unused;

  if (!dh->data.mem.buffer && dh->data.mem.orig_buffer)
    {
      size_t new_size = dh->data.mem.size;
      char *new_buffer;

      if (new_size < dh->data.mem.offset + size)
	new_size = dh->data.mem.offset + size;

      new_buffer = malloc (new_size);
      if (!new_buffer)
	return -1;
      memcpy (new_buffer, dh->data.mem.orig_buffer, dh->data.mem.length);

      dh->data.mem.buffer = new_buffer;
      dh->data.mem.size = new_size;
    }

  unused = dh->data.mem.size - dh->data.mem.offset;
  if (unused < size)
    {
      /* Allocate a large enough buffer with exponential backoff.  */
#define INITIAL_ALLOC 512
      size_t new_size = dh->data.mem.size
	? (2 * dh->data.mem.size) : INITIAL_ALLOC;
      char *new_buffer;

      if (new_size < dh->data.mem.offset + size)
	new_size = dh->data.mem.offset + size;

      new_buffer = realloc (dh->data.mem.buffer, new_size);
      if (!new_buffer && new_size > dh->data.mem.offset + size)
	{
	  /* Maybe we were too greedy, try again.  */
	  new_size = dh->data.mem.offset + size;
	  new_buffer = realloc (dh->data.mem.buffer, new_size);
	}
      if (!new_buffer)
	return -1;
      dh->data.mem.buffer = new_buffer;
      dh->data.mem.size = new_size;
    }

  memcpy (dh->data.mem.buffer + dh->data.mem.offset, buffer, size);
  dh->data.mem.offset += size;
  if (dh->data.mem.length < dh->data.mem.offset)
    dh->data.mem.length = dh->data.mem.offset;
  return size;
}


static gpgme_off_t
mem_seek (gpgme_data_t dh, gpgme_off_t offset, int whence)
{
  switch (whence)
    {
    case SEEK_SET:
      if (offset < 0 || offset > dh->data.mem.length)
	{
	  gpg_err_set_errno (EINVAL);
	  return -1;
	}
      dh->data.mem.offset = offset;
      break;
    case SEEK_CUR:
      if ((offset > 0 && dh->data.mem.length - dh->data.mem.offset < offset)
	  || (offset < 0 && dh->data.mem.offset < -offset))
	{
	  gpg_err_set_errno (EINVAL);
	  return -1;
	}
      dh->data.mem.offset += offset;
      break;
    case SEEK_END:
      if (offset > 0 || -offset > dh->data.mem.length)
	{
	  gpg_err_set_errno (EINVAL);
	  return -1;
	}
      dh->data.mem.offset = dh->data.mem.length + offset;
      break;
    default:
      gpg_err_set_errno (EINVAL);
      return -1;
    }
  return dh->data.mem.offset;
}


static void
mem_release (gpgme_data_t dh)
{
  if (dh->data.mem.buffer)
    free (dh->data.mem.buffer);
}


static struct _gpgme_data_cbs mem_cbs =
  {
    mem_read,
    mem_write,
    mem_seek,
    mem_release,
    NULL
  };


/* Create a new data buffer and return it in R_DH.  */
gpgme_error_t
gpgme_data_new (gpgme_data_t *r_dh)
{
  gpgme_error_t err;
  TRACE_BEG  (DEBUG_DATA, "gpgme_data_new", r_dh, "");

  err = _gpgme_data_new (r_dh, &mem_cbs);

  if (err)
    return TRACE_ERR (err);

  TRACE_SUC ("dh=%p", *r_dh);
  return 0;
}


/* Create a new data buffer filled with SIZE bytes starting from
   BUFFER.  If COPY is zero, copying is delayed until necessary, and
   the data is taken from the original location when needed.  */
gpgme_error_t
gpgme_data_new_from_mem (gpgme_data_t *r_dh, const char *buffer,
			 size_t size, int copy)
{
  gpgme_error_t err;
  TRACE_BEG  (DEBUG_DATA, "gpgme_data_new_from_mem", r_dh,
	      "buffer=%p, size=%zu, copy=%i (%s)", buffer, size,
	      copy, copy ? "yes" : "no");

  err = _gpgme_data_new (r_dh, &mem_cbs);
  if (err)
    return TRACE_ERR (err);

  if (copy)
    {
      char *bufcpy = malloc (size);
      if (!bufcpy)
	{
	  int saved_err = gpg_error_from_syserror ();
	  _gpgme_data_release (*r_dh);
	  return TRACE_ERR (saved_err);
	}
      memcpy (bufcpy, buffer, size);
      (*r_dh)->data.mem.buffer = bufcpy;
    }
  else
    (*r_dh)->data.mem.orig_buffer = buffer;

  (*r_dh)->data.mem.size = size;
  (*r_dh)->data.mem.length = size;
  TRACE_SUC ("dh=%p", *r_dh);
  return 0;
}


/* Destroy the data buffer DH and return a pointer to its content.
   The memory has be to released with gpgme_free() by the user.  It's
   size is returned in R_LEN.  */
char *
gpgme_data_release_and_get_mem (gpgme_data_t dh, size_t *r_len)
{
  gpg_error_t err;
  char *str = NULL;
  size_t len;
  int blankout;

  TRACE_BEG  (DEBUG_DATA, "gpgme_data_release_and_get_mem", dh,
	      "r_len=%p", r_len);

  if (!dh || dh->cbs != &mem_cbs)
    {
      gpgme_data_release (dh);
      TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));
      return NULL;
    }

  err = _gpgme_data_get_prop (dh, 0, DATA_PROP_BLANKOUT, &blankout);
  if (err)
    {
      gpgme_data_release (dh);
      TRACE_ERR (err);
      return NULL;
    }

  str = dh->data.mem.buffer;
  len = dh->data.mem.length;
  if (blankout && len)
    len = 1;

  if (!str && dh->data.mem.orig_buffer)
    {
      str = malloc (len);
      if (!str)
	{
	  int saved_err = gpg_error_from_syserror ();
	  gpgme_data_release (dh);
	  TRACE_ERR (saved_err);
	  return NULL;
	}
      if (blankout)
        memset (str, 0, len);
      else
        memcpy (str, dh->data.mem.orig_buffer, len);
    }
  else
    {
      if (blankout && len)
        *str = 0;
      /* Prevent mem_release from releasing the buffer memory.  We
       * must not fail from this point.  */
      dh->data.mem.buffer = NULL;
    }

  if (r_len)
    *r_len = len;

  gpgme_data_release (dh);

  if (r_len)
    TRACE_SUC ("buffer=%p, len=%zu", str, *r_len);
  else
    TRACE_SUC ("buffer=%p", str);
  return str;
}


/* Release the memory returned by gpgme_data_release_and_get_mem() and
   some other functions.  */
void
gpgme_free (void *buffer)
{
  TRACE (DEBUG_DATA, "gpgme_free", NULL, "p=%p", buffer);

  if (buffer)
    free (buffer);
}
