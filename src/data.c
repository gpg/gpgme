/* data.c - An abstraction for data objects.
 * Copyright (C) 2002, 2003, 2004, 2005, 2007 g10 Code GmbH
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

#include <stdlib.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "gpgme.h"
#include "data.h"
#include "util.h"
#include "ops.h"
#include "priv-io.h"
#include "debug.h"


/* The property table which has an entry for each active data object.
 * The data object itself uses an index into this table and the table
 * has a pointer back to the data object.  All access to that table is
 * controlled by the property_table_lock.
 *
 * We use a separate table instead of linking all data objects
 * together for faster locating properties of the data object using
 * the data objects serial number.  We use 64 bit for the serial
 * number which is good enough to create a new data object every
 * nanosecond for more than 500 years.  Thus no wrap around will ever
 * happen.
 */
struct property_s
{
  gpgme_data_t dh;   /* The data object or NULL if the slot is not used.  */
  uint64_t dserial;  /* The serial number of the data object.  */
  struct {
    unsigned int blankout : 1;  /* Void the held data.  */
  } flags;
};
typedef struct property_s *property_t;

static property_t property_table;
static unsigned int property_table_size;
DEFINE_STATIC_LOCK (property_table_lock);
#define PROPERTY_TABLE_ALLOCATION_CHUNK 32



/* Insert the newly created data object DH into the property table and
 * store the index of it at R_IDX.  An error code is returned on error
 * and the table is not changed.  */
static gpg_error_t
insert_into_property_table (gpgme_data_t dh, unsigned int *r_idx)
{
  static uint64_t last_dserial;
  gpg_error_t err;
  unsigned int idx;

  LOCK (property_table_lock);
  if (!property_table)
    {
      property_table_size = PROPERTY_TABLE_ALLOCATION_CHUNK;
      property_table = calloc (property_table_size, sizeof *property_table);
      if (!property_table)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  /* Find an empty slot.  */
  for (idx = 0; idx < property_table_size; idx++)
    if (!property_table[idx].dh)
      break;
  if (!(idx < property_table_size))
    {
      /* No empty slot found.  Enlarge the table.  */
      property_t newtbl;
      unsigned int newsize;

      newsize = property_table_size + PROPERTY_TABLE_ALLOCATION_CHUNK;;
      if ((newsize * sizeof *property_table)
          < (property_table_size * sizeof *property_table))
        {
          err = gpg_error (GPG_ERR_ENOMEM);
          goto leave;
        }
      newtbl = realloc (property_table, newsize * sizeof *property_table);
      if (!newtbl)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      property_table = newtbl;
      for (idx = property_table_size; idx < newsize; idx++)
        property_table[idx].dh = NULL;
      idx = property_table_size;
      property_table_size = newsize;
    }

  /* Slot found. */
  property_table[idx].dh = dh;
  property_table[idx].dserial = ++last_dserial;
  memset (&property_table[idx].flags, 0, sizeof property_table[idx].flags);
  *r_idx = idx;
  err = 0;

 leave:
  UNLOCK (property_table_lock);
  return err;
}


/* Remove the data object at PROPIDX from the table.  DH is only used
 * for cross checking.  */
static void
remove_from_property_table (gpgme_data_t dh, unsigned int propidx)
{
  LOCK (property_table_lock);
  assert (property_table);
  assert (propidx < property_table_size);
  assert (property_table[propidx].dh == dh);
  property_table[propidx].dh = NULL;
  UNLOCK (property_table_lock);
}


/* Return the data object's serial number for handle DH.  This is a
 * unique serial number for each created data object.  */
uint64_t
_gpgme_data_get_dserial (gpgme_data_t dh)
{
  uint64_t dserial;
  unsigned int idx;

  if (!dh)
    return 0;

  idx = dh->propidx;
  LOCK (property_table_lock);
  assert (property_table);
  assert (idx < property_table_size);
  assert (property_table[idx].dh == dh);
  dserial = property_table[idx].dserial;
  UNLOCK (property_table_lock);

  return dserial;
}


/* Set an internal property of a data object.  The data object may
 * either be identified by the usual DH or by using the data serial
 * number DSERIAL.  */
gpg_error_t
_gpgme_data_set_prop (gpgme_data_t dh, uint64_t dserial,
                      data_prop_t name, int value)
{
  gpg_error_t err = 0;
  int idx;
  TRACE_BEG  (DEBUG_DATA, "gpgme_data_set_prop", dh,
	      "dserial=%llu %lu=%d",
              (unsigned long long)dserial,
              (unsigned long)name, value);

  LOCK (property_table_lock);
  if ((!dh && !dserial) || (dh && dserial))
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }
  if (dh) /* Lookup via handle.  */
    {
      idx = dh->propidx;
      assert (property_table);
      assert (idx < property_table_size);
      assert (property_table[idx].dh == dh);
    }
  else /* Lookup via DSERIAL.  */
    {
      if (!property_table)
        {
          err = gpg_error (GPG_ERR_NOT_FOUND);
          goto leave;
        }
      for (idx = 0; idx < property_table_size; idx++)
        if (property_table[idx].dh && property_table[idx].dserial == dserial)
          break;
      if (!(idx < property_table_size))
        {
          err = gpg_error (GPG_ERR_NOT_FOUND);
          goto leave;
        }
    }

  switch (name)
    {
    case DATA_PROP_NONE: /* Nothing to to do.  */
      break;
    case DATA_PROP_BLANKOUT:
      property_table[idx].flags.blankout = !!value;
      break;

    default:
      err = gpg_error (GPG_ERR_UNKNOWN_NAME);
      break;
    }

 leave:
  UNLOCK (property_table_lock);
  return TRACE_ERR (err);
}


/* Get an internal property of a data object.  This is the counter
 * part to _gpgme_data_set_property.  The value of the property is
 * stored at R_VALUE.  On error 0 is stored at R_VALUE.  */
gpg_error_t
_gpgme_data_get_prop (gpgme_data_t dh, uint64_t dserial,
                      data_prop_t name, int *r_value)
{
  gpg_error_t err = 0;
  int idx;
  TRACE_BEG  (DEBUG_DATA, "gpgme_data_get_prop", dh,
	      "dserial=%llu %lu",
              (unsigned long long)dserial,
              (unsigned long)name);

  *r_value = 0;

  LOCK (property_table_lock);
  if ((!dh && !dserial) || (dh && dserial))
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }
  if (dh) /* Lookup via handle.  */
    {
      idx = dh->propidx;
      assert (property_table);
      assert (idx < property_table_size);
      assert (property_table[idx].dh == dh);
    }
  else /* Lookup via DSERIAL.  */
    {
      if (!property_table)
        {
          err = gpg_error (GPG_ERR_NOT_FOUND);
          goto leave;
        }
      for (idx = 0; idx < property_table_size; idx++)
        if (property_table[idx].dh && property_table[idx].dserial == dserial)
          break;
      if (!(idx < property_table_size))
        {
          err = gpg_error (GPG_ERR_NOT_FOUND);
          goto leave;
        }
    }

  switch (name)
    {
    case DATA_PROP_NONE: /* Nothing to to do.  */
      break;
    case DATA_PROP_BLANKOUT:
      *r_value = property_table[idx].flags.blankout;
      break;

    default:
      err = gpg_error (GPG_ERR_UNKNOWN_NAME);
      break;
    }

 leave:
  UNLOCK (property_table_lock);
  return TRACE_ERR (err);
}



gpgme_error_t
_gpgme_data_new (gpgme_data_t *r_dh, struct _gpgme_data_cbs *cbs)
{
  gpgme_error_t err;
  gpgme_data_t dh;

  if (!r_dh)
    return gpg_error (GPG_ERR_INV_VALUE);

  *r_dh = NULL;

  if (_gpgme_selftest)
    return _gpgme_selftest;

  dh = calloc (1, sizeof (*dh));
  if (!dh)
    return gpg_error_from_syserror ();

  dh->cbs = cbs;

  err = insert_into_property_table (dh, &dh->propidx);
  if (err)
    {
      free (dh);
      return err;
    }

  *r_dh = dh;
  return 0;
}


void
_gpgme_data_release (gpgme_data_t dh)
{
  if (!dh)
    return;

  remove_from_property_table (dh, dh->propidx);
  if (dh->file_name)
    free (dh->file_name);
  if (dh->inbound_buffer)
    {
      if (dh->sensitive)
        _gpgme_wipememory (dh->inbound_buffer, dh->io_buffer_size);
      free (dh->inbound_buffer);
    }
  if (dh->outbound_buffer)
    {
      if (dh->sensitive)
        _gpgme_wipememory (dh->outbound_buffer, dh->io_buffer_size);
      free (dh->outbound_buffer);
    }
  if (dh->sensitive)
    _gpgme_wipememory (dh->outboundspace, BUFFER_SIZE);

  free (dh);
}



/* Read up to SIZE bytes into buffer BUFFER from the data object with
   the handle DH.  Return the number of characters read, 0 on EOF and
   -1 on error.  If an error occurs, errno is set.  */
gpgme_ssize_t
gpgme_data_read (gpgme_data_t dh, void *buffer, size_t size)
{
  gpgme_ssize_t res;
  int blankout;
  TRACE_BEG  (DEBUG_DATA, "gpgme_data_read", dh,
	      "buffer=%p, size=%zu", buffer, size);

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

  if (_gpgme_data_get_prop (dh, 0, DATA_PROP_BLANKOUT, &blankout)
      || blankout)
    res = 0;
  else
    {
      do
        res = (*dh->cbs->read) (dh, buffer, size);
      while (res < 0 && errno == EINTR);
    }

  return TRACE_SYSRES_SSIZE_T (res);
}


/* Write up to SIZE bytes from buffer BUFFER to the data object with
   the handle DH.  Return the number of characters written, or -1 on
   error.  If an error occurs, errno is set.  */
gpgme_ssize_t
gpgme_data_write (gpgme_data_t dh, const void *buffer, size_t size)
{
  gpgme_ssize_t res;
  TRACE_BEG  (DEBUG_DATA, "gpgme_data_write", dh,
	      "buffer=%p, size=%zu", buffer, size);

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

  return TRACE_SYSRES_SSIZE_T (res);
}


/* Set the current position from where the next read or write starts
   in the data object with the handle DH to OFFSET, relative to
   WHENCE.  */
gpgme_off_t
gpgme_data_seek (gpgme_data_t dh, gpgme_off_t offset, int whence)
{
  TRACE_BEG  (DEBUG_DATA, "gpgme_data_seek", dh,
	      "offset=%lli, whence=%i", (long long int)offset, whence);

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
    offset -= dh->outbound_pending;

  offset = (*dh->cbs->seek) (dh, offset, whence);
  if (offset >= 0)
    dh->outbound_pending = 0;

  return TRACE_SYSRES_OFF_T (offset);
}


/* Convenience function to do a gpgme_data_seek (dh, 0, SEEK_SET).  */
gpgme_error_t
gpgme_data_rewind (gpgme_data_t dh)
{
  gpgme_error_t err;
  TRACE_BEG  (DEBUG_DATA, "gpgme_data_rewind", dh, "");

  err = ((gpgme_data_seek (dh, 0, SEEK_SET) == -1)
         ? gpg_error_from_syserror () : 0);

  return TRACE_ERR (err);
}


/* Release the data object with the handle DH.  */
void
gpgme_data_release (gpgme_data_t dh)
{
  TRACE (DEBUG_DATA, "gpgme_data_release", dh, "");

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
  TRACE (DEBUG_DATA, "gpgme_data_get_encoding", dh,
         "dh->encoding=%i", dh ? dh->encoding : GPGME_DATA_ENCODING_NONE);
  return dh ? dh->encoding : GPGME_DATA_ENCODING_NONE;
}


/* Set the encoding meta information for the data object with handle
   DH to ENC.  */
gpgme_error_t
gpgme_data_set_encoding (gpgme_data_t dh, gpgme_data_encoding_t enc)
{
  TRACE_BEG  (DEBUG_DATA, "gpgme_data_set_encoding", dh,
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
  TRACE_BEG  (DEBUG_DATA, "gpgme_data_set_file_name", dh,
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
      TRACE (DEBUG_DATA, "gpgme_data_get_file_name", dh, "");
      return NULL;
    }

  TRACE (DEBUG_DATA, "gpgme_data_get_file_name", dh,
         "dh->file_name=%s", dh->file_name);
  return dh->file_name;
}


/* Set a flag for the data object DH.  See the manual for details.  */
gpg_error_t
gpgme_data_set_flag (gpgme_data_t dh, const char *name, const char *value)
{
  TRACE_BEG  (DEBUG_DATA, "gpgme_data_set_flag", dh,
	      "%s=%s", name, value);

  if (!dh)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (!strcmp (name, "size-hint"))
    {
      dh->size_hint= value? _gpgme_string_to_off (value) : 0;
    }
  else if (!strcmp (name, "io-buffer-size"))
    {
      uint64_t val;

      /* We may set this only once.  */
      if (dh->io_buffer_size)
        return gpg_error (GPG_ERR_CONFLICT);

      val = value? _gpgme_string_to_off (value) : 0;
      if (val > 1024*1024)
        val = 1024*1024;  /* Cap at 1MiB */
      else if (val < BUFFER_SIZE)
        val = 0;          /* We can use the default buffer.  */

      /* Actual allocation happens as needed but we round it to a
       * multiple of 1k. */
      dh->io_buffer_size = ((val + 1023)/1024)*1024;
    }
  else if (!strcmp (name, "sensitive"))
    {
      dh->sensitive = (value && *value)? !!atoi (value) : 0;
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
  gpg_error_t err;
  gpgme_data_t dh = (gpgme_data_t) data->handler_value;
  char bufferspace[BUFFER_SIZE];
  char *buffer;
  size_t buffer_size;
  char *bufp;
  gpgme_ssize_t buflen;
  TRACE_BEG  (DEBUG_CTX, "_gpgme_data_inbound_handler", dh,
	      "fd=%d", fd);

  if (dh->io_buffer_size)
    {
      if (!dh->inbound_buffer)
        {
          dh->inbound_buffer = malloc (dh->io_buffer_size);
          if (!dh->inbound_buffer)
            return TRACE_ERR (gpg_error_from_syserror ());
        }
      buffer_size = dh->io_buffer_size;
      buffer = dh->inbound_buffer;
    }
  else
    {
      buffer_size = BUFFER_SIZE;
      buffer = bufferspace;
    }
  bufp = buffer;

  buflen = _gpgme_io_read (fd, buffer, buffer_size);
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
	{
          err = gpg_error_from_syserror ();
          goto leave;
        }
      bufp += amt;
      buflen -= amt;
    }
  while (buflen > 0);
  err = 0;

 leave:
  if (dh->sensitive && buffer == bufferspace)
    _gpgme_wipememory (bufferspace, BUFFER_SIZE);

  return TRACE_ERR (err);
}


gpgme_error_t
_gpgme_data_outbound_handler (void *opaque, int fd)
{
  struct io_cb_data *data = (struct io_cb_data *) opaque;
  gpgme_data_t dh = (gpgme_data_t) data->handler_value;
  char *buffer;
  size_t buffer_size;
  gpgme_ssize_t nwritten;
  TRACE_BEG  (DEBUG_CTX, "_gpgme_data_outbound_handler", dh,
	      "fd=%d", fd);

  if (dh->io_buffer_size)
    {
      if (!dh->outbound_buffer)
        {
          dh->outbound_buffer = malloc (dh->io_buffer_size);
          if (!dh->outbound_buffer)
            return TRACE_ERR (gpg_error_from_syserror ());
          dh->outbound_pending = 0;
        }
      buffer_size = dh->io_buffer_size;
      buffer = dh->outbound_buffer;
    }
  else
    {
      buffer_size = BUFFER_SIZE;
      buffer = dh->outboundspace;
    }


  if (!dh->outbound_pending)
    {
      gpgme_ssize_t amt = gpgme_data_read (dh, buffer, buffer_size);
      if (amt < 0)
	return TRACE_ERR (gpg_error_from_syserror ());
      if (amt == 0)
	{
	  _gpgme_io_close (fd);
	  return TRACE_ERR (0);
	}
      dh->outbound_pending = amt;
    }

  nwritten = _gpgme_io_write (fd, buffer, dh->outbound_pending);
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

  if (nwritten < dh->outbound_pending)
    memmove (buffer, buffer + nwritten, dh->outbound_pending - nwritten);
  dh->outbound_pending -= nwritten;
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
uint64_t
_gpgme_data_get_size_hint (gpgme_data_t dh)
{
  return dh ? dh->size_hint : 0;
}
