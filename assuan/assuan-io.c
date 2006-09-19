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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#if HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif
#include <unistd.h>
#include <errno.h>
#ifdef HAVE_W32_SYSTEM
# include <windows.h>
#else
# include <sys/wait.h>
#endif

#include "assuan-defs.h"

/* We can't include pth.h and we are not sure whether other headers
   already included it.  This we define macros with the same
   values. */
#define MY_PTH_FDMODE_ERROR    (-1)
#define MY_PTH_FDMODE_POLL     0
#define MY_PTH_FDMODE_BLOCK    1
#define MY_PTH_FDMODE_NONBLOCK 2


#ifndef _ASSUAN_NO_PTH
extern pid_t   pth_waitpid (pid_t pid, int *status, int options);
extern ssize_t pth_read (int fd, void *buffer, size_t size);
extern ssize_t pth_write (int fd, const void *buffer, size_t size);
extern int     pth_fdmode (int, int);
extern int     pth_select(int, fd_set*, fd_set*, fd_set*, struct timeval*);

#ifndef HAVE_W32_SYSTEM
#pragma weak pth_waitpid
#pragma weak pth_read
#pragma weak pth_write
#pragma weak pth_fdmode
#pragma weak pth_select
#endif
#endif /*!_ASSUAN_NO_PTH*/

#ifndef _ASSUAN_NO_PTH
/* Wrapper around pth_fdmode. */
static int
my_pth_fdmode (int fd, int mode)
{
  if (pth_fdmode)
    return pth_fdmode (fd, mode);
  else
    return MY_PTH_FDMODE_NONBLOCK; /* This is okay, given the way we use it. */
}
#endif /*_ASSUAN_NO_PTH*/

#ifndef _ASSUAN_NO_PTH
/* Wrapper around pth_select. */
static int 
my_pth_select (int nfd, fd_set *rfds, fd_set *wfds, fd_set *efds,
               struct timeval *timeout)
{
  if (pth_select)
    return pth_select (nfd, rfds, wfds, efds, timeout);
  else
    return 1; /* Fake one fd ready; this is okay, given the way we use it. */
}
#endif /*_ASSUAN_NO_PTH*/

#ifndef HAVE_W32_SYSTEM
pid_t 
_assuan_waitpid (pid_t pid, int *status, int options)
{
#ifdef _ASSUAN_NO_PTH
  return waitpid (pid, status, options);
#else
  return (pth_waitpid ? pth_waitpid : waitpid) (pid, status, options);
#endif
}
#endif


ssize_t
_assuan_simple_read (assuan_context_t ctx, void *buffer, size_t size)
{
#ifdef _ASSUAN_NO_PTH
  return read (ctx->inbound.fd, buffer, size);
#else
# ifndef HAVE_W32_SYSTEM
  return (pth_read ? pth_read : read) (ctx->inbound.fd, buffer, size);
# else
  return pth_read ? pth_read (ctx->inbound.fd, buffer, size)
                  : recv (ctx->inbound.fd, buffer, size, 0);
# endif
#endif
}

ssize_t
_assuan_simple_write (assuan_context_t ctx, const void *buffer, size_t size)
{
#ifdef _ASSUAN_NO_PTH
  return write (ctx->outbound.fd, buffer, size);
#else
# ifndef HAVE_W32_SYSTEM
  return (pth_write ? pth_write : write) (ctx->outbound.fd, buffer, size);
# else
  return pth_write ? pth_write (ctx->outbound.fd, buffer, size)
                   : send (ctx->outbound.fd, buffer, size, 0);
# endif
#endif
}


ssize_t
_assuan_simple_sendmsg (assuan_context_t ctx, struct msghdr *msg)
{
#if defined(HAVE_W32_SYSTEM)
  return _assuan_error (ASSUAN_Not_Implemented);
#elif defined(_ASSUAN_NO_PTH)
  int ret;
  while ( (ret = sendmsg (ctx->outbound.fd, msg, 0)) == -1 && errno == EINTR)
    ;
  return ret;
#else
  /* Pth does not provide a sendmsg function.  Thus we implement it here.  */
  int ret;
  int fd = ctx->outbound.fd;
  int fdmode;

  fdmode = my_pth_fdmode (fd, MY_PTH_FDMODE_POLL);
  if (fdmode == MY_PTH_FDMODE_ERROR)
    {
      errno = EBADF;
      return -1;
    }
  if (fdmode == MY_PTH_FDMODE_BLOCK)
    {
      fd_set fds;

      FD_ZERO (&fds);
      FD_SET (fd, &fds);
      while ( (ret = my_pth_select (fd+1, NULL, &fds, NULL, NULL)) < 0
              && errno == EINTR)
        ;
      if (ret < 0)
        return -1;
    }

  while ((ret = sendmsg (fd, msg, 0)) == -1 && errno == EINTR)
    ;
  return ret;
#endif
}


ssize_t
_assuan_simple_recvmsg (assuan_context_t ctx, struct msghdr *msg)
{
#if defined(HAVE_W32_SYSTEM)
  return _assuan_error (ASSUAN_Not_Implemented);
#elif defined(_ASSUAN_NO_PTH)
  int ret;
  while ( (ret = recvmsg (ctx->inbound.fd, msg, 0)) == -1 && errno == EINTR)
    ;
  return ret;
#else
  /* Pth does not provide a recvmsg function.  Thus we implement it here.  */
  int ret;
  int fd = ctx->inbound.fd;
  int fdmode;

  fdmode = my_pth_fdmode (fd, MY_PTH_FDMODE_POLL);
  if (fdmode == MY_PTH_FDMODE_ERROR)
    {
      errno = EBADF;
      return -1;
    }
  if (fdmode == MY_PTH_FDMODE_BLOCK)
    {
      fd_set fds;

      FD_ZERO (&fds);
      FD_SET (fd, &fds);
      while ( (ret = my_pth_select (fd+1, &fds, NULL, NULL, NULL)) < 0
              && errno == EINTR)
        ;
      if (ret < 0)
        return -1;
    }

  while ((ret = recvmsg (fd, msg, 0)) == -1 && errno == EINTR)
    ;
  return ret;
#endif
}
