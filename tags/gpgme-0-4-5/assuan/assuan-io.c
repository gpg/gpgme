/* assuan-io.c - Wraps the read and write functions.
 *	Copyright (C) 2002 Free Software Foundation, Inc.
 *
 * This file is part of Assuan.
 *
 * Assuan is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Assuan is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA 
 */

#include "assuan-defs.h"
#include <sys/types.h>
#include <unistd.h>

#ifdef _ASSUAN_IN_GPGME
ssize_t
_assuan_simple_read (ASSUAN_CONTEXT ctx, void *buffer, size_t size)
{
  return read (ctx->inbound.fd, buffer, size);
}

ssize_t
_assuan_simple_write (ASSUAN_CONTEXT ctx, const void *buffer, size_t size)
{
  return write (ctx->outbound.fd, buffer, size);
}

#else

extern ssize_t pth_read (int fd, void *buffer, size_t size);
extern ssize_t pth_write (int fd, const void *buffer, size_t size);

#pragma weak pth_read
#pragma weak pth_write

ssize_t
_assuan_simple_read (ASSUAN_CONTEXT ctx, void *buffer, size_t size)
{
  return (pth_read ? pth_read : read) (ctx->inbound.fd, buffer, size);
}

ssize_t
_assuan_simple_write (ASSUAN_CONTEXT ctx, const void *buffer, size_t size)
{
  return (pth_write ? pth_write : write) (ctx->outbound.fd, buffer, size);
}

#endif
