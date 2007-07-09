/* assuan-io.c - Wraps the read and write functions.
 *	Copyright (C) 2002, 2004, 2006 Free Software Foundation, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA. 
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/time.h>
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#include <unistd.h>
#include <errno.h>
#ifdef HAVE_W32_SYSTEM
# include <windows.h>
#else
# include <sys/wait.h>
#endif

#include "assuan-defs.h"


#ifndef HAVE_W32_SYSTEM
pid_t 
_assuan_waitpid (pid_t pid, int *status, int options)
{
  return waitpid (pid, status, options);
}
#endif


ssize_t
_assuan_simple_read (assuan_context_t ctx, void *buffer, size_t size)
{
#ifdef HAVE_W32_SYSTEM
  /* Due to the peculiarities of the W32 API we can't use read for a
     network socket and thus we try to use recv first and fallback to
     read if recv detects that it is not a network socket.  */
  int n;

  n = recv (ctx->inbound.fd, buffer, size, 0);
  if (n == -1 && WSAGetLastError () == WSAENOTSOCK)
    {
      DWORD nread = 0;

      n = ReadFile ((HANDLE)ctx->inbound.fd, buffer, size, &nread, NULL);
      if (!n)
        {
          errno = EIO; /* FIXME:  We should have a proper mapping.  */
          n = -1;
        }
      else
        n = (int)nread;
    }
  return n;
#else /*!HAVE_W32_SYSTEM*/
  return read (ctx->inbound.fd, buffer, size);
#endif /*!HAVE_W32_SYSTEM*/
}

ssize_t
_assuan_simple_write (assuan_context_t ctx, const void *buffer, size_t size)
{
#ifdef HAVE_W32_SYSTEM
  /* Due to the peculiarities of the W32 API we can't use write for a
     network socket and thus we try to use send first and fallback to
     write if send detects that it is not a network socket.  */
  int n;

  n = send (ctx->outbound.fd, buffer, size, 0);
  if (n == -1 && WSAGetLastError () == WSAENOTSOCK)
    {
      DWORD nwrite;

      n = WriteFile ((HANDLE)ctx->outbound.fd, buffer, size, &nwrite, NULL);
      if (!n)
        {
          errno = EIO; /* FIXME:  We should have a proper mapping.  */
          n = -1;
        }
      else
        n = (int)nwrite;
    }
  return n;
#else /*!HAVE_W32_SYSTEM*/
  return write (ctx->outbound.fd, buffer, size);
#endif /*!HAVE_W32_SYSTEM*/
}


#ifdef HAVE_W32_SYSTEM
int
_assuan_simple_sendmsg (assuan_context_t ctx, void *msg)
#else
ssize_t
_assuan_simple_sendmsg (assuan_context_t ctx, struct msghdr *msg)
#endif
{
#ifdef HAVE_W32_SYSTEM
  return _assuan_error (ASSUAN_Not_Implemented);
#else
  int ret;
  while ( (ret = sendmsg (ctx->outbound.fd, msg, 0)) == -1 && errno == EINTR)
    ;
  return ret;
#endif
}


#ifdef HAVE_W32_SYSTEM
int
_assuan_simple_recvmsg (assuan_context_t ctx, void *msg)
#else
ssize_t
_assuan_simple_recvmsg (assuan_context_t ctx, struct msghdr *msg)
#endif
{
#ifdef HAVE_W32_SYSTEM
  return _assuan_error (ASSUAN_Not_Implemented);
#else
  int ret;
  while ( (ret = recvmsg (ctx->inbound.fd, msg, 0)) == -1 && errno == EINTR)
    ;
  return ret;
#endif
}
