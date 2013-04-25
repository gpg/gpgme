/* data-fd.c - A file descripor based data object.
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

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include "debug.h"
#include "data.h"



#if defined(HAVE_W32CE_SYSTEM) && !defined(__MINGW32CE__)
/* We need to provide replacements for read, write and lseek.  They
   are taken from the cegcc runtime files, written by Pedro Alves
   <pedro_alves@portugalmail.pt> in Feb 2007 and placed in the public
   domain. (cf. cegcc/src/mingw/mingwex/wince/)  */

#include <windows.h>

static int
read (int fildes, void *buf, unsigned int bufsize)
{
  DWORD NumberOfBytesRead;
  if (bufsize > 0x7fffffff)
    bufsize = 0x7fffffff;
  if (!ReadFile ((HANDLE) fildes, buf, bufsize, &NumberOfBytesRead, NULL))
    return -1;
  return (int) NumberOfBytesRead;
}

static int
write (int fildes, const void *buf, unsigned int bufsize)
{
  DWORD NumberOfBytesWritten;
  if (bufsize > 0x7fffffff)
    bufsize = 0x7fffffff;
  if (!WriteFile ((HANDLE) fildes, buf, bufsize, &NumberOfBytesWritten, NULL))
    return -1;
  return (int) NumberOfBytesWritten;
}

static long
lseek (int fildes, long offset, int whence)
{
  DWORD mode;
  switch (whence)
    {
    case SEEK_SET:
      mode = FILE_BEGIN;
      break;
    case SEEK_CUR:
      mode = FILE_CURRENT;
      break;
    case SEEK_END:
      mode = FILE_END;
      break;
    default:
      /* Specify an invalid mode so SetFilePointer catches it.  */
      mode = (DWORD)-1;
    }
  return (long) SetFilePointer ((HANDLE) fildes, offset, NULL, mode);
}
#endif /*HAVE_W32CE_SYSTEM && !__MINGW32CE__*/



static gpgme_ssize_t
fd_read (gpgme_data_t dh, void *buffer, size_t size)
{
  return read (dh->data.fd, buffer, size);
}


static gpgme_ssize_t
fd_write (gpgme_data_t dh, const void *buffer, size_t size)
{
  return write (dh->data.fd, buffer, size);
}


static gpgme_off_t
fd_seek (gpgme_data_t dh, gpgme_off_t offset, int whence)
{
  return lseek (dh->data.fd, offset, whence);
}


static int
fd_get_fd (gpgme_data_t dh)
{
  return (dh->data.fd);
}


static struct _gpgme_data_cbs fd_cbs =
  {
    fd_read,
    fd_write,
    fd_seek,
    NULL,
    fd_get_fd
  };


gpgme_error_t
gpgme_data_new_from_fd (gpgme_data_t *r_dh, int fd)
{
  gpgme_error_t err;
  TRACE_BEG1 (DEBUG_DATA, "gpgme_data_new_from_fd", r_dh, "fd=0x%x", fd);

  err = _gpgme_data_new (r_dh, &fd_cbs);
  if (err)
    return TRACE_ERR (err);

  (*r_dh)->data.fd = fd;
  return TRACE_SUC1 ("dh=%p", *r_dh);
}
