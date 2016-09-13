/* data-compat.c - Compatibility interfaces for data objects.
   Copyright (C) 2002, 2003, 2004, 2007 g10 Code GmbH

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

#include <errno.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#include <stdlib.h>

#include "data.h"
#include "util.h"
#include "debug.h"


/* Create a new data buffer filled with LENGTH bytes starting from
   OFFSET within the file FNAME or stream STREAM (exactly one must be
   non-zero).  */
gpgme_error_t
gpgme_data_new_from_filepart (gpgme_data_t *r_dh, const char *fname,
			      FILE *stream, gpgme_off_t offset, size_t length)
{
#if defined (HAVE_W32CE_SYSTEM) && defined (_MSC_VER)
  return gpgme_error (GPG_ERR_NOT_IMPLEMENTED);
#else
  gpgme_error_t err;
  char *buf = NULL;
  int res;

  TRACE_BEG4 (DEBUG_DATA, "gpgme_data_new_from_filepart", r_dh,
	      "file_name=%s, stream=%p, offset=%lli, length=%u",
	      fname, stream, offset, length);

  if (stream && fname)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (fname)
    stream = fopen (fname, "rb");
  if (!stream)
    return TRACE_ERR (gpg_error_from_syserror ());

#ifdef HAVE_FSEEKO
  res = fseeko (stream, offset, SEEK_SET);
#else
  /* FIXME: Check for overflow, or at least bail at compilation.  */
  res = fseek (stream, offset, SEEK_SET);
#endif

  if (res)
    {
      int saved_err = gpg_error_from_syserror ();
      if (fname)
	fclose (stream);
      return TRACE_ERR (saved_err);
    }

  buf = malloc (length);
  if (!buf)
    {
      int saved_err = gpg_error_from_syserror ();
      if (fname)
	fclose (stream);
      return TRACE_ERR (saved_err);
    }

  while (fread (buf, length, 1, stream) < 1
	 && ferror (stream) && errno == EINTR);
  if (ferror (stream))
    {
      int saved_err = gpg_error_from_syserror ();
      if (buf)
	free (buf);
      if (fname)
	fclose (stream);
      return TRACE_ERR (saved_err);
    }

  if (fname)
    fclose (stream);

  err = gpgme_data_new (r_dh);
  if (err)
    {
      if (buf)
	free (buf);
      return err;
    }

  (*r_dh)->data.mem.buffer = buf;
  (*r_dh)->data.mem.size = length;
  (*r_dh)->data.mem.length = length;

  return TRACE_SUC1 ("r_dh=%p", *r_dh);
#endif
}


/* Create a new data buffer filled with the content of file FNAME.
   COPY must be non-zero (delayed reads are not supported yet).  */
gpgme_error_t
gpgme_data_new_from_file (gpgme_data_t *r_dh, const char *fname, int copy)
{
#if defined (HAVE_W32CE_SYSTEM) && defined (_MSC_VER)
  return gpgme_error (GPG_ERR_NOT_IMPLEMENTED);
#else
  gpgme_error_t err;
  struct stat statbuf;
  TRACE_BEG3 (DEBUG_DATA, "gpgme_data_new_from_file", r_dh,
	      "file_name=%s, copy=%i (%s)", fname, copy, copy ? "yes" : "no");

  if (!fname || !copy)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (stat (fname, &statbuf) < 0)
    return TRACE_ERR (gpg_error_from_syserror ());

  err = gpgme_data_new_from_filepart (r_dh, fname, NULL, 0, statbuf.st_size);
  return TRACE_ERR (err);
#endif
}


static int
gpgme_error_to_errno (gpgme_error_t err)
{
  int res = gpg_err_code_to_errno (gpg_err_code (err));

  if (!err)
    {
      switch (gpg_err_code (err))
	{
	case GPG_ERR_EOF:
	  res = 0;
	  break;
	case GPG_ERR_INV_VALUE:
	  res = EINVAL;
	  break;
	case GPG_ERR_NOT_SUPPORTED:
	  res = ENOSYS;
	  break;
	default:
	  /* FIXME: Yeah, well.  */
	  res = EINVAL;
	  break;
	}
    }
  TRACE3 (DEBUG_DATA, "gpgme:gpgme_error_to_errno", 0,
	  "mapping %s <%s> to: %s", gpgme_strerror (err),
	  gpgme_strsource (err), strerror (res));
  gpg_err_set_errno (res);
  return res ? -1 : 0;
}


static gpgme_ssize_t
old_user_read (gpgme_data_t dh, void *buffer, size_t size)
{
  gpgme_error_t err;
  size_t amt;
  TRACE_BEG2 (DEBUG_DATA, "gpgme:old_user_read", dh,
	      "buffer=%p, size=%u", buffer, size);

  err = (*dh->data.old_user.cb) (dh->data.old_user.handle,
				 buffer, size, &amt);
  if (err)
    return TRACE_SYSRES (gpgme_error_to_errno (err));
  return TRACE_SYSRES ((gpgme_ssize_t)amt);
}


static gpgme_off_t
old_user_seek (gpgme_data_t dh, gpgme_off_t offset, int whence)
{
  gpgme_error_t err;
  TRACE_BEG2 (DEBUG_DATA, "gpgme:old_user_seek", dh,
	      "offset=%llu, whence=%i", offset, whence);

  if (whence != SEEK_SET || offset)
    {
      gpg_err_set_errno (EINVAL);
      return TRACE_SYSRES (-1);
    }
  err = (*dh->data.old_user.cb) (dh->data.old_user.handle, NULL, 0, NULL);
  if (err)
    return TRACE_SYSRES (gpgme_error_to_errno (err));
  return TRACE_SYSRES (0);
}


static struct _gpgme_data_cbs old_user_cbs =
  {
    old_user_read,
    NULL,
    old_user_seek,
    NULL
  };


/* Create a new data buffer which retrieves the data from the callback
   function READ_CB.  */
gpgme_error_t
gpgme_data_new_with_read_cb (gpgme_data_t *r_dh,
                             int (*read_cb) (void *, char *, size_t, size_t *),
                             void *read_cb_value)
{
  gpgme_error_t err;
  TRACE_BEG2 (DEBUG_DATA, "gpgme_data_new_with_read_cb", r_dh,
	      "read_cb=%p/%p", read_cb, read_cb_value);

  err = _gpgme_data_new (r_dh, &old_user_cbs);

  if (err)
    return TRACE_ERR (err);

  (*r_dh)->data.old_user.cb = read_cb;
  (*r_dh)->data.old_user.handle = read_cb_value;
  return TRACE_ERR (0);
}


gpgme_error_t
gpgme_data_rewind (gpgme_data_t dh)
{
  gpgme_error_t err;
  TRACE_BEG (DEBUG_DATA, "gpgme_data_rewind", dh);

  err = ((gpgme_data_seek (dh, 0, SEEK_SET) == -1)
         ? gpg_error_from_syserror () : 0);

  return TRACE_ERR (err);
}
