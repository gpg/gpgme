/* data.h - Internal data object abstraction interface.
   Copyright (C) 2002, 2004, 2005 g10 Code GmbH

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

#ifndef DATA_H
#define DATA_H

#if HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <limits.h>
#include <stdint.h>

#include "gpgme.h"

/* Figure out the standard size for internal data buffers.  */
#ifdef PIPE_BUF
# define BUFFER_SIZE PIPE_BUF
#else
# ifdef _POSIX_PIPE_BUF
#  define BUFFER_SIZE _POSIX_PIPE_BUF
# else
#  ifdef HAVE_W32_SYSTEM
#   define BUFFER_SIZE 4096
#  else
#   define BUFFER_SIZE 512
#  endif
# endif
#endif



/* Read up to SIZE bytes into buffer BUFFER from the data object with
   the handle DH.  Return the number of characters read, 0 on EOF and
   -1 on error.  If an error occurs, errno is set.  */
typedef gpgme_ssize_t (*gpgme_data_read_cb) (gpgme_data_t dh,
                                             void *buffer,
                                             size_t size);

/* Write up to SIZE bytes from buffer BUFFER to the data object with
   the handle DH.  Return the number of characters written, or -1 on
   error.  If an error occurs, errno is set.  */
typedef gpgme_ssize_t (*gpgme_data_write_cb) (gpgme_data_t dh,
                                              const void *buffer,
                                              size_t size);

/* Set the current position from where the next read or write starts
   in the data object with the handle DH to OFFSET, relative to
   WHENCE.  */
typedef gpgme_off_t (*gpgme_data_seek_cb) (gpgme_data_t dh,
                                            gpgme_off_t offset,
                                            int whence);

/* Release the data object with the handle DH.  */
typedef void (*gpgme_data_release_cb) (gpgme_data_t dh);

/* Get the FD associated with the handle DH, or -1.  */
typedef int (*gpgme_data_get_fd_cb) (gpgme_data_t dh);

struct _gpgme_data_cbs
{
  gpgme_data_read_cb read;
  gpgme_data_write_cb write;
  gpgme_data_seek_cb seek;
  gpgme_data_release_cb release;
  gpgme_data_get_fd_cb get_fd;
};

struct gpgme_data
{
  struct _gpgme_data_cbs *cbs;
  gpgme_data_encoding_t encoding;
  unsigned int propidx;  /* Index into the property table.  */

  /* File name of the data object.  */
  char *file_name;

  /* Hint on the to be expected total size of the data.  */
  uint64_t size_hint;

  /* If no 0 the size of an allocated inbound or outpund buffers.  The
   * value is at least BUFFER_SIZE and capped at 1MiB.  */
  unsigned int io_buffer_size;

  /* If not NULL a malloced buffer used for inbound data used instead
   * of the handler's static buffer.  Its size is io_buffer_size.  */
  char *inbound_buffer;

  /* A default memory space for the outbound handler and the number of
   * actual pending bytes.  If outbound_buffer is not NULL, this is a
   * malloced buffer used instead of the outboundspace.  Its malloced
   * size is io_buffer_size. */
  char outboundspace[BUFFER_SIZE];
  unsigned int outbound_pending;
  char *outbound_buffer;

  /* If set sensitive data is conveyed via the internal buffer.  This
   * flags overwrites the memory of the buffers with zero before they
   * are released. */
  unsigned int sensitive:1;

  union
  {
    /* For gpgme_data_new_from_fd.  */
    int fd;

    /* For gpgme_data_new_from_stream.  */
    FILE *stream;

    /* For gpgme_data_new_from_estream.  */
    gpgrt_stream_t e_stream;

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
      gpgme_off_t offset;
    } mem;

    /* For gpgme_data_new_from_read_cb.  */
    struct
    {
      int (*cb) (void *, char *, size_t, size_t *);
      void *handle;
    } old_user;
  } data;
};


/* The data property types.  */
typedef enum
  {
    DATA_PROP_NONE = 0,   /* Dummy property. */
    DATA_PROP_BLANKOUT    /* Do not return the held data.  */
  } data_prop_t;



/* Return the data object's serial number for handle DH.  */
uint64_t _gpgme_data_get_dserial (gpgme_data_t dh);

/* Set an internal property of a data object.  */
gpg_error_t _gpgme_data_set_prop (gpgme_data_t dh, uint64_t dserial,
                                  data_prop_t name, int value);

/* Get an internal property of a data object.  */
gpg_error_t _gpgme_data_get_prop (gpgme_data_t dh, uint64_t dserial,
                                  data_prop_t name, int *r_value);

/* Create a new data object.  */
gpgme_error_t _gpgme_data_new (gpgme_data_t *r_dh,
			       struct _gpgme_data_cbs *cbs);

void _gpgme_data_release (gpgme_data_t dh);

/* Get the file descriptor associated with DH, if possible.  Otherwise
   return -1.  */
int _gpgme_data_get_fd (gpgme_data_t dh);

/* Get the size-hint value for DH or 0 if not available.  */
uint64_t _gpgme_data_get_size_hint (gpgme_data_t dh);


#endif	/* DATA_H */
