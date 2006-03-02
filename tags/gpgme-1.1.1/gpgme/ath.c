/* ath.c - Thread-safeness library.
   Copyright (C) 2002, 2003, 2004 g10 Code GmbH

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <unistd.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#else
# include <sys/time.h>
#endif
#include <sys/types.h>
#ifndef HAVE_W32_SYSTEM
#include <sys/wait.h>
#endif

#include "ath.h"


#define MUTEX_UNLOCKED	((ath_mutex_t) 0)
#define MUTEX_LOCKED	((ath_mutex_t) 1)
#define MUTEX_DESTROYED	((ath_mutex_t) 2)


int
ath_mutex_init (ath_mutex_t *lock)
{
#ifndef NDEBUG
  *lock = MUTEX_UNLOCKED;
#endif
  return 0;
}


int
ath_mutex_destroy (ath_mutex_t *lock)
{
#ifndef NDEBUG
  assert (*lock == MUTEX_UNLOCKED);

  *lock = MUTEX_DESTROYED;
#endif
  return 0;
}


int
ath_mutex_lock (ath_mutex_t *lock)
{
#ifndef NDEBUG
  assert (*lock == MUTEX_UNLOCKED);

  *lock = MUTEX_LOCKED;
#endif
  return 0;
}


int
ath_mutex_unlock (ath_mutex_t *lock)
{
#ifndef NDEBUG
  assert (*lock == MUTEX_LOCKED);

  *lock = MUTEX_UNLOCKED;
#endif
  return 0;
}


ssize_t
ath_read (int fd, void *buf, size_t nbytes)
{
  return read (fd, buf, nbytes);
}


ssize_t
ath_write (int fd, const void *buf, size_t nbytes)
{
  return write (fd, buf, nbytes);
}


ssize_t
ath_select (int nfd, fd_set *rset, fd_set *wset, fd_set *eset,
	    struct timeval *timeout)
{
#ifdef HAVE_W32_SYSTEM
  return -1; /* Not supported. */
#else
  return select (nfd, rset, wset, eset, timeout);
#endif
}

 
ssize_t
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
