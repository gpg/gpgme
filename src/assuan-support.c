/* assuan-support.c - Assuan wrappers
 * Copyright (C) 2009 g10 Code GmbH
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

#include <assert.h>
#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifndef HAVE_W32_SYSTEM
#include <unistd.h>
#include <sys/wait.h>
#endif

#include "assuan.h"

#include "gpgme.h"
#include "priv-io.h"
#include "debug.h"


struct assuan_malloc_hooks _gpgme_assuan_malloc_hooks =
  {
    malloc,
    realloc,
    free
  };


int
_gpgme_assuan_log_cb (assuan_context_t ctx, void *hook,
		      unsigned int cat, const char *msg)
{
  (void)ctx;
  (void)hook;
  (void)cat;

  if (msg == NULL)
    return 1;

  _gpgme_debug (NULL, DEBUG_ASSUAN, -1, NULL, NULL, NULL, "%s", msg);
  return 0;
}


static void
my_usleep (assuan_context_t ctx, unsigned int usec)
{
  (void)ctx;

  if (!usec)
    return;

#ifdef HAVE_W32_SYSTEM
  Sleep (usec / 1000);
#else
# ifdef HAVE_NANOSLEEP
  {
    struct timespec req;
    struct timespec rem;

    req.tv_sec  = usec / 1000000;
    req.tv_nsec = (usec % 1000000) * 1000;
    while (nanosleep (&req, &rem) < 0 && errno == EINTR)
      req = rem;
  }
# else
  usleep (usec);
# endif
#endif
}


/* Create a pipe with an inheritable end.  */
static int
my_pipe (assuan_context_t ctx, assuan_fd_t fds[2], int inherit_idx)
{
  int res;
  int gfds[2];

  (void)ctx;

  res = _gpgme_io_pipe (gfds, inherit_idx);

  /* For now... */
  fds[0] = (assuan_fd_t) gfds[0];
  fds[1] = (assuan_fd_t) gfds[1];

  return res;
}


/* Close the given file descriptor, created with _assuan_pipe or one
   of the socket functions.  */
static int
my_close (assuan_context_t ctx, assuan_fd_t fd)
{
  (void)ctx;
  return _gpgme_io_close ((int) fd);
}


static gpgme_ssize_t
my_read (assuan_context_t ctx, assuan_fd_t fd, void *buffer, size_t size)
{
  (void)ctx;
  return _gpgme_io_read ((int) fd, buffer, size);
}


static gpgme_ssize_t
my_write (assuan_context_t ctx, assuan_fd_t fd, const void *buffer, size_t size)
{
  (void)ctx;
  return _gpgme_io_write ((int) fd, buffer, size);
}


static int
my_recvmsg (assuan_context_t ctx, assuan_fd_t fd, assuan_msghdr_t msg,
	    int flags)
{
  (void)ctx;
#ifdef HAVE_W32_SYSTEM
  (void)fd;
  (void)msg;
  (void)flags;
  gpg_err_set_errno (ENOSYS);
  return -1;
#else
  return _gpgme_io_recvmsg ((int) fd, msg, flags);
#endif
}



static int
my_sendmsg (assuan_context_t ctx, assuan_fd_t fd, const assuan_msghdr_t msg,
	    int flags)
{
  (void)ctx;
#ifdef HAVE_W32_SYSTEM
  (void)fd;
  (void)msg;
  (void)flags;
  gpg_err_set_errno (ENOSYS);
  return -1;
#else
  return _gpgme_io_sendmsg ((int) fd, msg, flags);
#endif
}


/* If NAME is NULL, don't exec, just fork.  FD_CHILD_LIST is modified
   to reflect the value of the FD in the peer process (on
   Windows).  */
static int
my_spawn (assuan_context_t ctx, pid_t *r_pid, const char *name,
	  const char **argv,
	  assuan_fd_t fd_in, assuan_fd_t fd_out,
	  assuan_fd_t *fd_child_list,
	  void (*atfork) (void *opaque, int reserved),
	  void *atforkvalue, unsigned int flags)
{
  int err = 0;
  struct spawn_fd_item_s *fd_items;
  int i;

  (void)ctx;
  (void)flags;

  assert (name);

  if (! name)
    {
      gpg_err_set_errno (ENOSYS);
      return -1;
    }

  i = 0;
  if (fd_child_list)
    {
      while (fd_child_list[i] != ASSUAN_INVALID_FD)
	i++;
    }
  /* fd_in, fd_out, terminator */
  i += 3;
  fd_items = calloc (i, sizeof (struct spawn_fd_item_s));
  if (! fd_items)
    return -1;
  i = 0;
  if (fd_child_list)
    {
      while (fd_child_list[i] != ASSUAN_INVALID_FD)
	{
	  fd_items[i].fd = (int) fd_child_list[i];
	  fd_items[i].dup_to = -1;
	  i++;
	}
    }
  if (fd_in != ASSUAN_INVALID_FD)
    {
      fd_items[i].fd = (int) fd_in;
      fd_items[i].dup_to = 0;
      i++;
    }
  if (fd_out != ASSUAN_INVALID_FD)
    {
      fd_items[i].fd = (int) fd_out;
      fd_items[i].dup_to = 1;
      i++;
    }
  fd_items[i].fd = -1;
  fd_items[i].dup_to = -1;

#ifdef HAVE_W32_SYSTEM
  /* Fix up a potential logger fd so that on windows the fd
   * translation can work through gpgme-w32spawn.
   *
   * We do this here as a hack because we would
   * otherwise have to change assuan_api and the current
   * plan in 2019 is to change away from this to gpgrt
   * based IPC. */
  if (argv)
    {
      int loc = 0;
      while (argv[loc])
        {
          if (!strcmp ("--logger-fd", argv[loc]))
            {
              long logger_fd = -1;
              char *tail;
              int k = 0;
              loc++;
              if (!argv[loc])
                {
                  err = GPG_ERR_INV_ARG;
                  break;
                }
              logger_fd = strtol (argv[loc], &tail, 10);
              if (tail == argv[loc] || logger_fd < 0)
                {
                  err = GPG_ERR_INV_ARG;
                  break;
                }
              while (fd_items[k++].fd != -1)
                {
                  if (fd_items[k].fd == logger_fd)
                    {
                      fd_items[k].arg_loc = loc;
                      break;
                    }
                }
              break;
            }
          loc++;
        }
    }
#endif

  if (!err)
    {
      err = _gpgme_io_spawn (name, (char*const*)argv,
                             (IOSPAWN_FLAG_NOCLOSE | IOSPAWN_FLAG_DETACHED),
                             fd_items, atfork, atforkvalue, r_pid);
    }
  if (!err)
    {
      i = 0;

      if (fd_child_list)
	{
	  while (fd_child_list[i] != ASSUAN_INVALID_FD)
	    {
	      fd_child_list[i] = (assuan_fd_t) fd_items[i].peer_name;
	      i++;
	    }
	}
    }
  free (fd_items);
  return err;
}


/* If action is 0, like waitpid.  If action is 1, just release the PID?  */
static pid_t
my_waitpid (assuan_context_t ctx, pid_t pid,
	    int nowait, int *status, int options)
{
  (void)ctx;
#ifdef HAVE_W32_SYSTEM
  (void)nowait;
  (void)status;
  (void)options;
  (void)pid;  /* Just a number without a kernel object.  */
#else
  /* We can't just release the PID, a waitpid is mandatory.  But
     NOWAIT in POSIX systems just means the caller already did the
     waitpid for this child.  */
  if (! nowait)
    return waitpid (pid, status, options);
#endif
  return 0;
}




static int
my_socketpair (assuan_context_t ctx, int namespace, int style,
	       int protocol, assuan_fd_t filedes[2])
{
  (void)ctx;
#ifdef HAVE_W32_SYSTEM
  (void)namespace;
  (void)style;
  (void)protocol;
  (void)filedes;
  gpg_err_set_errno (ENOSYS);
  return -1;
#else
  /* FIXME: Debug output missing.  */
  return socketpair (namespace, style, protocol, filedes);
#endif
}


static int
my_socket (assuan_context_t ctx, int namespace, int style, int protocol)
{
  (void)ctx;
  return _gpgme_io_socket (namespace, style, protocol);
}


static int
my_connect (assuan_context_t ctx, int sock, struct sockaddr *addr,
	    socklen_t length)
{
  (void)ctx;
  return _gpgme_io_connect (sock, addr, length);
}


/* Note for Windows: Ignore the incompatible pointer type warning for
   my_read and my_write.  Mingw has been changed to use int for
   ssize_t on 32 bit systems while we use long.  For 64 bit we use
   int64_t while mingw uses __int64_t.  It does not matter at all
   because under Windows long and int are both 32 bit even on 64
   bit.  */
struct assuan_system_hooks _gpgme_assuan_system_hooks =
  {
    ASSUAN_SYSTEM_HOOKS_VERSION,
    my_usleep,
    my_pipe,
    my_close,
    my_read,
    my_write,
    my_recvmsg,
    my_sendmsg,
    my_spawn,
    my_waitpid,
    my_socketpair,
    my_socket,
    my_connect
  };
