/* data.h - Internal data object abstraction interface.
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

#ifndef DATA_H
#define DATA_H

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <limits.h>

#include "gpgme.h"


/* Read up to SIZE bytes into buffer BUFFER from the data object with
   the handle DH.  Return the number of characters read, 0 on EOF and
   -1 on error.  If an error occurs, errno is set.  */
typedef ssize_t (*gpgme_data_read_cb) (gpgme_data_t dh, void *buffer,
				       size_t size);

/* Write up to SIZE bytes from buffer BUFFER to the data object with
   the handle DH.  Return the number of characters written, or -1 on
   error.  If an error occurs, errno is set.  */
typedef ssize_t (*gpgme_data_write_cb) (gpgme_data_t dh, const void *buffer,
					size_t size);

/* Set the current position from where the next read or write starts
   in the data object with the handle DH to OFFSET, relativ to
   WHENCE.  */
typedef off_t (*gpgme_data_seek_cb) (gpgme_data_t dh, off_t offset,
				     int whence);

/* Release the data object with the handle DH.  */
typedef void (*gpgme_data_release_cb) (gpgme_data_t dh);

struct _gpgme_data_cbs
{
  gpgme_data_read_cb read;
  gpgme_data_write_cb write;
  gpgme_data_seek_cb seek;
  gpgme_data_release_cb release;
};

struct gpgme_data
{
  struct _gpgme_data_cbs *cbs;
  gpgme_data_encoding_t encoding;

#ifdef PIPE_BUF
#define BUFFER_SIZE PIPE_BUF
#else
#ifdef _POSIX_PIPE_BUF
#define BUFFER_SIZE _POSIX_PIPE_BUF
#else
#define BUFFER_SIZE 512
#endif
#endif
  char pending[BUFFER_SIZE];
  int pending_len;

  union
  {
    /* For gpgme_data_new_from_fd.  */
    int fd;

    /* For gpgme_data_new_from_stream.  */
    FILE *stream;

    /* For gpgme_data_new_from_cbs.  */
    struct
    {
      gpgme_data_cbs_t cbs;
      void *handle;
    } user;

    /* For gpgme_data_new_from_mem.  */
    struct
    {
      char *buffer;
      const char *orig_buffer;
      /* Allocated size of BUFFER.  */
      size_t size;
      size_t length;
      size_t offset;
    } mem;

    /* For gpgme_data_new_from_read_cb.  */
    struct
    {
      int (*cb) (void *, char *, size_t, size_t *);
      void *handle;
    } old_user;
  } data;
};


gpgme_error_t _gpgme_data_new (gpgme_data_t *r_dh,
			       struct _gpgme_data_cbs *cbs);

void _gpgme_data_release (gpgme_data_t dh);

#endif	/* DATA_H */
