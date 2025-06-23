/* posix-io.c - Posix I/O functions
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2004, 2005, 2007, 2010 g10 Code GmbH
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
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <sys/wait.h>
#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif
#include <ctype.h>
#include <sys/resource.h>

#ifdef USE_LINUX_GETDENTS
# include <sys/syscall.h>
# include <sys/types.h>
# include <dirent.h>
#endif /*USE_LINUX_GETDENTS*/

#ifdef HAVE_POLL_H
# include <poll.h>
#else
# ifdef HAVE_SYS_SELECT_H
#  include <sys/select.h>
# endif
#endif
#include <sys/socket.h>

#include "util.h"
#include "priv-io.h"
#include "sema.h"
#include "debug.h"


#ifdef USE_LINUX_GETDENTS
/* This is not declared in public headers; getdents64(2) says that we must
 * define it ourselves.  */
struct linux_dirent64
{
  ino64_t d_ino;
  off64_t d_off;
  unsigned short d_reclen;
  unsigned char d_type;
  char d_name[];
};

# define DIR_BUF_SIZE 1024
#endif /*USE_LINUX_GETDENTS*/


/* Return true if FD is valid file descriptor.  */
#if 0
int
_gpgme_is_fd_valid (int fd)
{
  int dir_fd;
  char dir_buf[DIR_BUF_SIZE];
  struct linux_dirent64 *dir_entry;
  int r, pos, x;
  const char *s;
  int result = 0;

  dir_fd = open ("/proc/self/fd", O_RDONLY | O_DIRECTORY);
  if (dir_fd != -1)
    {
      for (;;)
        {
          r = syscall(SYS_getdents64, dir_fd, dir_buf, DIR_BUF_SIZE);
          if (r == -1)
            break;  /* Ooops */
          if (r == 0)
            break;

          for (pos = 0; pos < r; pos += dir_entry->d_reclen)
            {
              dir_entry = (struct linux_dirent64 *) (dir_buf + pos);
              s = dir_entry->d_name;
              if (*s < '0' || *s > '9')
                continue;
              /* atoi is not guaranteed to be async-signal-safe.  */
              for (x = 0; *s >= '0' && *s <= '9'; s++)
                x = x * 10 + (*s - '0');
              if (*s)
                continue;  /* Does not look like a file descriptor.  */
              if (x == fd)
                {
                  result = 1;
                  goto leave;
                }
            }
        }
    leave:
      close (dir_fd);
    }
  return result;
}
#endif /*0*/


/* Fallback value for max_fds for some systems.  It can be used later
   in get_max_fds function.  */
static int max_fds_fallback;

void
_gpgme_io_subsystem_init (void)
{
  struct sigaction act;

  sigaction (SIGPIPE, NULL, &act);
  if (act.sa_handler == SIG_DFL)
    {
      act.sa_handler = SIG_IGN;
      sigemptyset (&act.sa_mask);
      act.sa_flags = 0;
      sigaction (SIGPIPE, &act, NULL);
    }

  max_fds_fallback = -1;

#ifdef _SC_OPEN_MAX
  if (max_fds_fallback == -1)
    {
      /* For multithread application, sysconf cannot be used in the
       * forked child process (in get_max_fds function), since it is
       * not async-signal-safe function.  Here, we can assume it's
       * only a single thread.
       */
      long scres = sysconf (_SC_OPEN_MAX);

      if (scres >= 0)
        max_fds_fallback = scres;
    }
#endif
}


/* Write the printable version of FD to the buffer BUF of length
   BUFLEN.  The printable version is the representation on the command
   line that the child process expects.  */
int
_gpgme_io_fd2str (char *buf, int buflen, int fd)
{
  return snprintf (buf, buflen, "%d", fd);
}


/* The table to hold notification handlers.  We use a linear search
   and extend the table as needed.  */
struct notify_table_item_s
{
  int fd;  /* -1 indicates an unused entry.  */
  _gpgme_close_notify_handler_t handler;
  void *value;
};
typedef struct notify_table_item_s *notify_table_item_t;

static notify_table_item_t notify_table;
static size_t notify_table_size;
DEFINE_STATIC_LOCK (notify_table_lock);



int
_gpgme_io_read (int fd, void *buffer, size_t count)
{
  int nread;
  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_read", NULL,
	      "fd=%d buffer=%p count=%zu", fd, buffer, count);

  do
    {
      nread = read (fd, buffer, count);
    }
  while (nread == -1 && errno == EINTR);

  TRACE_LOGBUFX (buffer, nread);
  return TRACE_SYSRES (nread);
}


int
_gpgme_io_write (int fd, const void *buffer, size_t count)
{
  int nwritten;
  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_write", NULL,
	      "fd=%d buffer=%p count=%zu", fd, buffer, count);
  TRACE_LOGBUFX (buffer, count);

  do
    {
      nwritten = write (fd, buffer, count);
    }
  while (nwritten == -1 && errno == EINTR);

  return TRACE_SYSRES (nwritten);
}


int
_gpgme_io_pipe (int filedes[2], int inherit_idx)
{
  int saved_errno;
  int err;
  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_pipe", NULL,
	      "inherit_idx=%i (GPGME uses it for %s)",
	      inherit_idx, inherit_idx ? "reading" : "writing");

  err = pipe (filedes);
  if (err < 0)
    return TRACE_SYSRES (err);

  /* FIXME: Should get the old flags first.  */
  err = fcntl (filedes[1 - inherit_idx], F_SETFD, FD_CLOEXEC);
  saved_errno = errno;
  if (err < 0)
    {
      close (filedes[0]);
      close (filedes[1]);
    }
  errno = saved_errno;
  if (err)
    return TRACE_SYSRES (err);

  TRACE_SUC ("read fd=%d write fd=%d", filedes[0], filedes[1]);
  return 0;
}


int
_gpgme_io_close (int fd)
{
  int res;
  _gpgme_close_notify_handler_t handler = NULL;
  void *handler_value;
  int idx;

  TRACE_BEG (DEBUG_SYSIO, "_gpgme_io_close", NULL, "fd=%d", fd);

  if (fd == -1)
    {
      errno = EINVAL;
      return TRACE_SYSRES (-1);
    }

  /* First call the notify handler.  */
  LOCK (notify_table_lock);
  for (idx=0; idx < notify_table_size; idx++)
    {
      if (notify_table[idx].fd == fd)
        {
	  handler       = notify_table[idx].handler;
	  handler_value = notify_table[idx].value;
	  notify_table[idx].handler = NULL;
	  notify_table[idx].value = NULL;
	  notify_table[idx].fd = -1; /* Mark slot as free.  */
          break;
        }
    }
  UNLOCK (notify_table_lock);
  if (handler)
    {
      TRACE_LOG  ("invoking close handler %p/%p", handler, handler_value);
      handler (fd, handler_value);
    }

  /* Then do the close.  */
  res = close (fd);
  return TRACE_SYSRES (res);
}


int
_gpgme_io_set_close_notify (int fd, _gpgme_close_notify_handler_t handler,
			    void *value)
{
  int res = 0;
  int idx;

  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_set_close_notify", NULL,
	      "fd=%d close_handler=%p/%p", fd, handler, value);

  assert (fd != -1);

  LOCK (notify_table_lock);
  for (idx=0; idx < notify_table_size; idx++)
    if (notify_table[idx].fd == -1)
      break;
  if (idx == notify_table_size)
    {
      /* We need to increase the size of the table.  The approach we
         take is straightforward to minimize the risk of bugs.  */
      notify_table_item_t newtbl;
      size_t newsize = notify_table_size + 64;

      newtbl = calloc (newsize, sizeof *newtbl);
      if (!newtbl)
        {
          res = -1;
          goto leave;
        }
      for (idx=0; idx < notify_table_size; idx++)
        newtbl[idx] = notify_table[idx];
      for (; idx < newsize; idx++)
        {
          newtbl[idx].fd = -1;
          newtbl[idx].handler = NULL;
          newtbl[idx].value = NULL;
        }
      free (notify_table);
      notify_table = newtbl;
      idx = notify_table_size;
      notify_table_size = newsize;
    }
  notify_table[idx].fd = fd;
  notify_table[idx].handler = handler;
  notify_table[idx].value = value;

 leave:
  UNLOCK (notify_table_lock);

  return TRACE_SYSRES (res);
}


int
_gpgme_io_set_nonblocking (int fd)
{
  int flags;
  int res;
  TRACE_BEG (DEBUG_SYSIO, "_gpgme_io_set_nonblocking", NULL, "fd=%d", fd);

  flags = fcntl (fd, F_GETFL, 0);
  if (flags == -1)
    return TRACE_SYSRES (-1);
  flags |= O_NONBLOCK;
  res = fcntl (fd, F_SETFL, flags);
  return TRACE_SYSRES (res);
}


static int
get_max_fds (void)
{
  const char *source = NULL;
  long int fds = -1;
  int rc;

  /* Under Linux we can figure out the highest used file descriptor by
   * reading /proc/self/fd.  This is in the common cases much faster
   * than for example doing 4096 close calls where almost all of them
   * will fail.
   *
   * We can't use the normal opendir/readdir/closedir interface between
   * fork and exec in a multi-threaded process because opendir uses
   * malloc and thus a mutex which may deadlock with a malloc in another
   * thread.  However, the underlying getdents system call is safe.  */
#ifdef USE_LINUX_GETDENTS
  {
    int dir_fd;
    struct linux_dirent64 buf[(DIR_BUF_SIZE+sizeof (struct linux_dirent64)-1)
                              /sizeof (struct linux_dirent64)];
    char *dir_buf = (char *)buf; /* BUF aligned for struct linux_dirent64 */
    struct linux_dirent64 *dir_entry;
    long r, pos;
    const char *s;
    int x;

    dir_fd = open ("/proc/self/fd", O_RDONLY | O_DIRECTORY);
    if (dir_fd != -1)
      {
        for (;;)
          {
            r = syscall(SYS_getdents64, dir_fd, dir_buf, sizeof (buf));
            if (r == -1)
              {
                /* Fall back to other methods.  */
                fds = -1;
                break;
              }
            if (r == 0)
              break;

            for (pos = 0; pos < r; pos += dir_entry->d_reclen)
              {
                dir_entry = (struct linux_dirent64 *) (dir_buf + pos);
                s = dir_entry->d_name;
                if (*s < '0' || *s > '9')
                  continue;
                /* atoi is not guaranteed to be async-signal-safe.  */
                for (x = 0; *s >= '0' && *s <= '9'; s++)
                  x = x * 10 + (*s - '0');
                if (!*s && x > fds && x != dir_fd)
                  fds = x;
              }
          }

        close (dir_fd);
      }
    if (fds != -1)
      {
        fds++;
        source = "/proc";
      }
    }
#endif /*USE_LINUX_GETDENTS*/

#ifdef RLIMIT_NOFILE
  if (fds == -1)
    {
      struct rlimit rl;
      rc = getrlimit (RLIMIT_NOFILE, &rl);
      if (rc == 0)
        {
          source = "RLIMIT_NOFILE";
          fds = rl.rlim_max;
        }
    }
#endif
#ifdef RLIMIT_OFILE
  if (fds == -1)
    {
      struct rlimit rl;
      rc = getrlimit (RLIMIT_OFILE, &rl);
      if (rc == 0)
	{
	  source = "RLIMIT_OFILE";
	  fds = rl.rlim_max;
	}
    }
#endif

  if (fds == -1 && max_fds_fallback >= 0)
    {
      source = "fallback";
      return max_fds_fallback;
    }

#ifdef OPEN_MAX
  if (fds == -1)
    {
      source = "OPEN_MAX";
      fds = OPEN_MAX;
    }
#endif

#if !defined(RLIMIT_NOFILE) && !defined(RLIMIT_OFILE) \
  && !defined(_SC_OPEN_MAX) && !defined(OPEN_MAX)
#warning "No known way to get the maximum number of file descriptors."
#endif
  if (fds == -1)
    {
      source = "arbitrary";
      /* Arbitrary limit.  */
      fds = 1024;
    }

  /* AIX returns INT32_MAX instead of a proper value.  We assume that
   * this is always an error and use a more reasonable limit.  */
#ifdef INT32_MAX
  if (fds == INT32_MAX)
    {
      source = "aix-fix";
      fds = 1024;
    }
#endif

#if 0 /* This may result hang in multi-thread application.  */
  TRACE (DEBUG_SYSIO, "gpgme:max_fds", NULL, "max fds=%ld (%s)", fds, source);
#else
  (void)source;
#endif
  return fds;
}


int
_gpgme_io_waitpid (int pid, int hang, int *r_status, int *r_signal)
{
  int status;
  pid_t ret;

  *r_status = 0;
  *r_signal = 0;
  do
    ret = waitpid (pid, &status, hang? 0 : WNOHANG);
  while (ret == (pid_t)(-1) && errno == EINTR);

  if (ret == pid)
    {
      if (WIFSIGNALED (status))
	{
	  *r_status = 4; /* Need some value here.  */
	  *r_signal = WTERMSIG (status);
	}
      else if (WIFEXITED (status))
	*r_status = WEXITSTATUS (status);
      else
	*r_status = 4; /* Oops.  */
      return 1;
    }
  return 0;
}


/* Returns 0 on success, -1 on error.  */
int
_gpgme_io_spawn (const char *path, char *const argv[], unsigned int flags,
		 struct spawn_fd_item_s *fd_list,
		 void (*atfork) (void *opaque, int reserved),
		 void *atforkvalue, pid_t *r_pid)
{
  pid_t pid;
  int i;
  int status;
  int signo;

  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_spawn", NULL,
	      "path=%s", path);
  i = 0;
  while (argv[i])
    {
      TRACE_LOG  ("argv[%2i] = %s", i, argv[i]);
      i++;
    }
  for (i = 0; fd_list[i].fd != -1; i++)
    {
      if (fd_list[i].dup_to == -1)
        TRACE_LOG  ("fd[%i] = 0x%x", i, fd_list[i].fd);
      else
        TRACE_LOG  ("fd[%i] = 0x%x -> 0x%x", i,fd_list[i].fd,fd_list[i].dup_to);
    }

  pid = fork ();
  if (pid == -1)
    return TRACE_SYSRES (-1);

  if (!pid)
    {
      /* Intermediate child to prevent zombie processes.  */
      if ((pid = fork ()) == 0)
	{
	  /* Child.  */
          int max_fds = -1;
          int fd;
	  int seen_stdin = 0;
	  int seen_stdout = 0;
	  int seen_stderr = 0;

	  if (atfork)
	    atfork (atforkvalue, 0);

          /* First close all fds which will not be inherited.  If we
           * have closefrom(2) we first figure out the highest fd we
           * do not want to close, then call closefrom, and on success
           * use the regular code to close all fds up to the start
           * point of closefrom.  Note that Solaris' and FreeBSD's closefrom do
           * not return errors.  */
#ifdef HAVE_CLOSEFROM
          {
            fd = -1;
            for (i = 0; fd_list[i].fd != -1; i++)
              if (fd_list[i].fd > fd)
                fd = fd_list[i].fd;
            fd++;
#if defined(__sun) || defined(__FreeBSD__) || defined(__GLIBC__)
            closefrom (fd);
            max_fds = fd;
#else /*!__sun */
            while ((i = closefrom (fd)) && errno == EINTR)
              ;
            if (!i || errno == EBADF)
              max_fds = fd;
#endif /*!__sun*/
          }
#endif /*HAVE_CLOSEFROM*/
          if (max_fds == -1)
            max_fds = get_max_fds ();
          for (fd = 0; fd < max_fds; fd++)
            {
              for (i = 0; fd_list[i].fd != -1; i++)
                if (fd_list[i].fd == fd)
                  break;
              if (fd_list[i].fd == -1)
                close (fd);
            }

	  /* And now dup and close those to be duplicated.  */
	  for (i = 0; fd_list[i].fd != -1; i++)
	    {
	      int child_fd;
	      int res;

	      if (fd_list[i].dup_to != -1)
		child_fd = fd_list[i].dup_to;
	      else
		child_fd = fd_list[i].fd;

	      if (child_fd == 0)
		seen_stdin = 1;
	      else if (child_fd == 1)
		seen_stdout = 1;
	      else if (child_fd == 2)
		seen_stderr = 1;

	      if (fd_list[i].dup_to == -1)
		continue;

	      res = dup2 (fd_list[i].fd, fd_list[i].dup_to);
	      if (res < 0)
		{
#if 0
		  /* FIXME: The debug file descriptor is not
		     dup'ed anyway, so we can't see this.  */
		  TRACE_LOG  ("dup2 failed in child: %s\n",
			      strerror (errno));
#endif
		  _exit (8);
		}

	      close (fd_list[i].fd);
	    }

	  if (! seen_stdin || ! seen_stdout || !seen_stderr)
	    {
	      fd = open ("/dev/null", O_RDWR);
	      if (fd == -1)
		{
		  /* The debug file descriptor is not dup'ed, so we
		     can't do a trace output.  */
		  _exit (8);
		}
	      /* Make sure that the process has connected stdin.  */
	      if (! seen_stdin && fd != 0)
		{
		  if (dup2 (fd, 0) == -1)
                    _exit (8);
		}
	      if (! seen_stdout && fd != 1)
                {
                  if (dup2 (fd, 1) == -1)
                    _exit (8);
                }
	      if (! seen_stderr && fd != 2)
                {
                  if (dup2 (fd, 2) == -1)
                    _exit (8);
                }
	      if (fd != 0 && fd != 1 && fd != 2)
		close (fd);
	    }

	  execv (path, (char *const *) argv);
	  /* Hmm: in that case we could write a special status code to the
	     status-pipe.  */
	  _exit (8);
	  /* End child.  */
	}
      if (pid == -1)
	_exit (1);
      else
	_exit (0);
    }

  TRACE_LOG  ("waiting for child process pid=%i", pid);
  _gpgme_io_waitpid (pid, 1, &status, &signo);
  if (status)
    return TRACE_SYSRES (-1);

  for (i = 0; fd_list[i].fd != -1; i++)
    {
      if (! (flags & IOSPAWN_FLAG_NOCLOSE))
	_gpgme_io_close (fd_list[i].fd);
      /* No handle translation.  */
      fd_list[i].peer_name = fd_list[i].fd;
    }

  if (r_pid)
    *r_pid = pid;

  return TRACE_SYSRES (0);
}


/* Select on the list of fds.  Returns: -1 = error, 0 = timeout or
   nothing to select, > 0 = number of signaled fds.  */
#ifdef HAVE_POLL_H
static int
_gpgme_io_select_poll (struct io_select_fd_s *fds, size_t nfds, int nonblock)
{
  struct pollfd *poll_fds = NULL;
  nfds_t poll_nfds;
  /* Use a 1s timeout.  */
  int timeout = 1000;
  unsigned int i;
  int any;
  int count;
  void *dbg_help = NULL;
  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_select", NULL,
	      "nfds=%zu, nonblock=%u", nfds, nonblock);


  if (nonblock)
    timeout = 0;

  poll_fds = malloc (sizeof (*poll_fds)*nfds);
  if (!poll_fds)
    return -1;

  poll_nfds = 0;

  TRACE_SEQ (dbg_help, "poll on [ ");

  any = 0;
  for (i = 0; i < nfds; i++)
    {
      if (fds[i].fd == -1)
	continue;
      if (fds[i].for_read || fds[i].for_write)
	{
          poll_fds[poll_nfds].fd = fds[i].fd;
          poll_fds[poll_nfds].events = 0;
          poll_fds[poll_nfds].revents = 0;
          if (fds[i].for_read)
            {
              poll_fds[poll_nfds].events |= POLLIN;
              TRACE_ADD1 (dbg_help, "r=%d ", fds[i].fd);
            }
          if (fds[i].for_write)
            {
              poll_fds[poll_nfds].events |= POLLOUT;
              TRACE_ADD1 (dbg_help, "w=%d ", fds[i].fd);
            }
          poll_nfds++;
          any = 1;
        }
      fds[i].signaled = 0;
    }
  TRACE_END (dbg_help, "]");
  if (!any)
    {
      free (poll_fds);
      return TRACE_SYSRES (0);
    }

  do
    count = poll (poll_fds, poll_nfds, timeout);
  while (count < 0 && (errno == EINTR || errno == EAGAIN));
  if (count < 0)
    {
      int save_errno = errno;
      free (poll_fds);
      errno = save_errno;
      return TRACE_SYSRES (-1);
    }

  TRACE_SEQ (dbg_help, "poll OK [ ");
  if (TRACE_ENABLED (dbg_help))
    {
      poll_nfds = 0;
      for (i = 0; i < nfds; i++)
	{
          if (fds[i].fd == -1)
            continue;
	  if ((poll_fds[poll_nfds].revents & (POLLIN|POLLHUP)))
	    TRACE_ADD2 (dbg_help, "r=%d (%x) ", fds[i].fd,
                        (int)poll_fds[poll_nfds].revents);
	  if ((poll_fds[poll_nfds].revents & POLLOUT))
	    TRACE_ADD1 (dbg_help, "w=%d ", fds[i].fd);
          poll_nfds++;
        }
      TRACE_END (dbg_help, "]");
    }

  poll_nfds = 0;
  for (i = 0; i < nfds; i++)
    {
      if (fds[i].fd == -1)
	continue;
      if (fds[i].for_read || fds[i].for_write)
	{
          short events_to_be_checked = 0;

          if (fds[i].for_read)
            events_to_be_checked |= (POLLIN|POLLHUP);
          if (fds[i].for_write)
            events_to_be_checked |= POLLOUT;
          if ((poll_fds[poll_nfds].revents & events_to_be_checked))
            fds[i].signaled = 1;

          poll_nfds++;
        }
    }

  free (poll_fds);
  return TRACE_SYSRES (count);
}
#else
static int
_gpgme_io_select_select (struct io_select_fd_s *fds, size_t nfds, int nonblock)
{
  fd_set readfds;
  fd_set writefds;
  unsigned int i;
  int any;
  int max_fd;
  int n;
  int count;
  /* Use a 1s timeout.  */
  struct timeval timeout = { 1, 0 };
  void *dbg_help = NULL;
  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_select", NULL,
	      "nfds=%zu, nonblock=%u", nfds, nonblock);

  FD_ZERO (&readfds);
  FD_ZERO (&writefds);
  max_fd = 0;
  if (nonblock)
    timeout.tv_sec = 0;

  TRACE_SEQ (dbg_help, "select on [ ");

  any = 0;
  for (i = 0; i < nfds; i++)
    {
      if (fds[i].fd == -1)
	continue;
      if (fds[i].for_read)
	{
          if (fds[i].fd >= FD_SETSIZE)
            {
              TRACE_END (dbg_help, " -BAD- ]");
              gpg_err_set_errno (EMFILE);
              return TRACE_SYSRES (-1);
            }
	  assert (!FD_ISSET (fds[i].fd, &readfds));
	  FD_SET (fds[i].fd, &readfds);
	  if (fds[i].fd > max_fd)
	    max_fd = fds[i].fd;
	  TRACE_ADD1 (dbg_help, "r=%d ", fds[i].fd);
          any = 1;
        }
      else if (fds[i].for_write)
	{
          if (fds[i].fd >= FD_SETSIZE)
            {
              TRACE_END (dbg_help, " -BAD- ]");
              gpg_err_set_errno (EMFILE);
              return TRACE_SYSRES (-1);
            }
	  assert (!FD_ISSET (fds[i].fd, &writefds));
	  FD_SET (fds[i].fd, &writefds);
	  if (fds[i].fd > max_fd)
	    max_fd = fds[i].fd;
	  TRACE_ADD1 (dbg_help, "w=%d ", fds[i].fd);
	  any = 1;
        }
      fds[i].signaled = 0;
    }
  TRACE_END (dbg_help, "]");
  if (!any)
    return TRACE_SYSRES (0);

  do
    {
      count = select (max_fd + 1, &readfds, &writefds, NULL, &timeout);
    }
  while (count < 0 && errno == EINTR);
  if (count < 0)
    return TRACE_SYSRES (-1);

  TRACE_SEQ (dbg_help, "select OK [ ");
  if (TRACE_ENABLED (dbg_help))
    {
      for (i = 0; i <= max_fd; i++)
	{
	  if (FD_ISSET (i, &readfds))
	    TRACE_ADD1 (dbg_help, "r=%d ", i);
	  if (FD_ISSET (i, &writefds))
	    TRACE_ADD1 (dbg_help, "w=%d ", i);
        }
      TRACE_END (dbg_help, "]");
    }

  /* The variable N is used to optimize it a little bit.  */
  for (n = count, i = 0; i < nfds && n; i++)
    {
      if (fds[i].fd == -1)
	;
      else if (fds[i].for_read)
	{
	  if (FD_ISSET (fds[i].fd, &readfds))
	    {
	      fds[i].signaled = 1;
	      n--;
            }
        }
      else if (fds[i].for_write)
	{
	  if (FD_ISSET (fds[i].fd, &writefds))
	    {
	      fds[i].signaled = 1;
	      n--;
            }
        }
    }
  return TRACE_SYSRES (count);
}
#endif

int
_gpgme_io_select (struct io_select_fd_s *fds, size_t nfds, int nonblock)
{
#ifdef HAVE_POLL_H
  return _gpgme_io_select_poll (fds, nfds, nonblock);
#else
  return _gpgme_io_select_select (fds, nfds, nonblock);
#endif
}

int
_gpgme_io_recvmsg (int fd, struct msghdr *msg, int flags)
{
  int nread;
  int saved_errno;
  struct iovec *iov;
  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_recvmsg", NULL,
	      "fd=%d msg=%p flags=%i", fd, msg, flags);

  nread = 0;
  iov = msg->msg_iov;
  while (iov < msg->msg_iov + msg->msg_iovlen)
    {
      nread += iov->iov_len;
      iov++;
    }

  TRACE_LOG  ("about to receive %d bytes", nread);

  do
    {
      nread = recvmsg (fd, msg, flags);
    }
  while (nread == -1 && errno == EINTR);
  saved_errno = errno;
  if (nread > 0)
    {
      int nr = nread;

      iov = msg->msg_iov;
      while (nr > 0)
	{
	  int len = nr > iov->iov_len ? iov->iov_len : nr;
	  TRACE_LOGBUFX (msg->msg_iov->iov_base, len);
	  iov++;
	  nr -= len;
	}
    }
  errno = saved_errno;
  return TRACE_SYSRES (nread);
}


int
_gpgme_io_sendmsg (int fd, const struct msghdr *msg, int flags)
{
  int nwritten;
  struct iovec *iov;
  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_sendmsg", NULL,
	      "fd=%d msg=%p flags=%i", fd, msg, flags);

  nwritten = 0;
  iov = msg->msg_iov;
  while (iov < msg->msg_iov + msg->msg_iovlen)
    {
      nwritten += iov->iov_len;
      iov++;
    }

  TRACE_LOG  ("about to receive %d bytes", nwritten);
  iov = msg->msg_iov;
  while (nwritten > 0)
    {
      int len = nwritten > iov->iov_len ? iov->iov_len : nwritten;
      TRACE_LOGBUFX (msg->msg_iov->iov_base, len);
      iov++;
      nwritten -= len;
    }

  do
    {
      nwritten = sendmsg (fd, msg, flags);
    }
  while (nwritten == -1 && errno == EINTR);
  return TRACE_SYSRES (nwritten);
}


int
_gpgme_io_dup (int fd)
{
  int new_fd;

  do
    new_fd = dup (fd);
  while (new_fd == -1 && errno == EINTR);

  TRACE (DEBUG_SYSIO, "_gpgme_io_dup", NULL, "fd=%d -> fd=%d", fd, new_fd);

  return new_fd;
}


int
_gpgme_io_socket (int domain, int type, int proto)
{
  int res;

  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_socket", NULL,
	      "domain=%d type=%i proto=%i", domain, type, proto);

  res = socket (domain, type, proto);

  return TRACE_SYSRES (res);
}


int
_gpgme_io_connect (int fd, struct sockaddr *addr, int addrlen)
{
  int res;

  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_connect", NULL,
	      "fd=%d addr=%p addrlen=%i", fd, addr, addrlen);

  do
    res = connect (fd, addr, addrlen);
  while (res == -1 && errno == EINTR);

  return TRACE_SYSRES (res);
}
