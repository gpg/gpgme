/* data-mem.c - A memory based data object.
   Copyright (C) 2002, 2003 g10 Code GmbH
 
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

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>

#include "data.h"
#include "util.h"


static ssize_t
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


static ssize_t
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


static off_t
mem_seek (gpgme_data_t dh, off_t offset, int whence)
{
  switch (whence)
    {
    case SEEK_SET:
      if (offset < 0 || offset > dh->data.mem.length)
	{
	  errno = EINVAL;
	  return -1;
	}
      dh->data.mem.offset = offset;
      break;
    case SEEK_CUR:
      if ((offset > 0 && dh->data.mem.length - dh->data.mem.offset < offset)
	  || (offset < 0 && dh->data.mem.offset < -offset)) 
	{
	  errno = EINVAL;
	  return -1;
	}
      dh->data.mem.offset += offset;
      break;
    case SEEK_END:
      if (offset > 0 || -offset > dh->data.mem.length)
	{
	  errno = EINVAL;
	  return -1;
	}
      dh->data.mem.offset = dh->data.mem.length - offset;
      break;
    default:
      errno = EINVAL;
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
    mem_release
  };


gpgme_error_t
gpgme_data_new (gpgme_data_t *dh)
{
  gpgme_error_t err = _gpgme_data_new (dh, &mem_cbs);
  if (err)
    return err;

  return 0;
}


/* Create a new data buffer filled with SIZE bytes starting from
   BUFFER.  If COPY is zero, copying is delayed until necessary, and
   the data is taken from the original location when needed.  */
gpgme_error_t
gpgme_data_new_from_mem (gpgme_data_t *dh, const char *buffer,
			 size_t size, int copy)
{
  gpgme_error_t err = _gpgme_data_new (dh, &mem_cbs);
  if (err)
    return err;

  if (copy)
    {
      char *bufcpy = malloc (size);
      if (!bufcpy)
	_gpgme_data_release (*dh);
      memcpy (bufcpy, buffer, size);
      (*dh)->data.mem.buffer = bufcpy;
    }
  else
    (*dh)->data.mem.orig_buffer = buffer;
  
  (*dh)->data.mem.size = size;
  (*dh)->data.mem.length = size;
  return 0;
}


char *
gpgme_data_release_and_get_mem (gpgme_data_t dh, size_t *r_len)
{
  char *str = NULL;

  if (!dh || dh->cbs != &mem_cbs)
    return NULL;

  str = dh->data.mem.buffer;
  if (!str && dh->data.mem.orig_buffer)
    {
      str = malloc (dh->data.mem.length);
      if (!str)
	return NULL;
      memcpy (str, dh->data.mem.orig_buffer, dh->data.mem.length);
    }

  if (r_len)
    *r_len = dh->data.mem.length;

  return str;
}
