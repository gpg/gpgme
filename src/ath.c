/* ath.c - Thread-safeness library.
 * Copyright (C) 2002, 2003, 2004 g10 Code GmbH
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_POLL_H
# include <poll.h>
#else
# ifdef HAVE_SYS_SELECT_H
#  include <sys/select.h>
# else
#  ifdef HAVE_SYS_TIME_H
#   include <sys/time.h>
#  endif
# endif
#endif
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifndef HAVE_W32_SYSTEM
#include <sys/wait.h>
#endif

#include "gpgme.h"

#ifdef _MSC_VER
  typedef int  pid_t;
#endif

#include "ath.h"


#ifdef HAVE_W32_SYSTEM
#include <windows.h>
uintptr_t
ath_self (void)
{
  return (uintptr_t) GetCurrentThreadId ();
}
#else
# ifdef __linux
#include <sys/syscall.h>
uintptr_t
ath_self (void)
{
  /* Just to catch users who don't use gpgme-pthread.  */
  return (uintptr_t) syscall (__NR_gettid);
}
# else
uintptr_t
ath_self (void)
{
  return (uintptr_t) getpid ();
}
# endif
#endif


gpgme_ssize_t
ath_read (int fd, void *buf, size_t nbytes)
{
  return read (fd, buf, nbytes);
}


gpgme_ssize_t
ath_write (int fd, const void *buf, size_t nbytes)
{
  return write (fd, buf, nbytes);
}


#if !defined(HAVE_POLL_H)
gpgme_ssize_t
ath_select (int nfd, fd_set *rset, fd_set *wset, fd_set *eset,
	    struct timeval *timeout)
{
#ifdef HAVE_W32_SYSTEM
  return -1; /* Not supported. */
#else
  return select (nfd, rset, wset, eset, timeout);
#endif
}
#endif

gpgme_ssize_t
ath_waitpid (pid_t pid, int *status, int options)
{
#ifdef HAVE_W32_SYSTEM
  return -1; /* Not supported. */
#else
  return waitpid (pid, status, options);
#endif
}


int
ath_accept (int s, struct sockaddr *addr, socklen_t *length_ptr)
{
#ifdef HAVE_W32_SYSTEM
  return -1; /* Not supported. */
#else
  return accept (s, addr, length_ptr);
#endif
}


int
ath_connect (int s, const struct sockaddr *addr, socklen_t length)
{
#ifdef HAVE_W32_SYSTEM
  return -1; /* Not supported. */
#else
  return connect (s, addr, length);
#endif
}


int
ath_sendmsg (int s, const struct msghdr *msg, int flags)
{
#ifdef HAVE_W32_SYSTEM
  return -1; /* Not supported. */
#else
  return sendmsg (s, msg, flags);
#endif
}


int
ath_recvmsg (int s, struct msghdr *msg, int flags)
{
#ifdef HAVE_W32_SYSTEM
  return -1; /* Not supported. */
#else
  return recvmsg (s, msg, flags);
#endif
}
