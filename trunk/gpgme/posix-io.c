/* posix-io.c - Posix I/O functions
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002 g10 Code GmbH

   This file is part of GPGME.
 
   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with GPGME; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "util.h"
#include "io.h"
#include "sema.h"
#include "ath.h"
#include "debug.h"


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
}


static struct
{
  void (*handler) (int,void*);
  void *value;
} notify_table[256];

int
_gpgme_io_read (int fd, void *buffer, size_t count)
{
  int nread;
  int saved_errno;

  DEBUG2 ("fd %d: about to read %d bytes\n", fd, (int) count);
  do
    {
      nread = _gpgme_ath_read (fd, buffer, count);
    }
  while (nread == -1 && errno == EINTR);
  saved_errno = errno;
  DEBUG2 ("fd %d: got %d bytes\n", fd, nread);
  if (nread > 0)
    _gpgme_debug (2, "fd %d: got `%.*s'\n", fd, nread, buffer);
  errno = saved_errno;
  return nread;
}


int
_gpgme_io_write (int fd, const void *buffer, size_t count)
{
  int saved_errno;
  int nwritten;

  DEBUG2 ("fd %d: about to write %d bytes\n", fd, (int) count);
  _gpgme_debug (2, "fd %d: write `%.*s'\n", fd, (int) count, buffer);
  do
    {
      nwritten = _gpgme_ath_write (fd, buffer, count);
    }
  while (nwritten == -1 && errno == EINTR);
  saved_errno = errno;
  DEBUG2 ("fd %d:          wrote %d bytes\n", fd, (int) nwritten);
  errno = saved_errno;
  return nwritten;
}


int
_gpgme_io_pipe (int filedes[2], int inherit_idx)
{
  int saved_errno;
  int err;

  err = pipe (filedes);
  if (err < 0)
    return err;
  /* FIXME: Should get the old flags first.  */
  err = fcntl (filedes[1 - inherit_idx], F_SETFD, FD_CLOEXEC);
  saved_errno = errno;
  if (err < 0)
    {
      close (filedes[0]);
      close (filedes[1]);
    }
  errno = saved_errno;
  return err;
}


int
_gpgme_io_close (int fd)
{
  if (fd == -1)
    return -1;
  /* First call the notify handler.  */
  DEBUG1 ("closing fd %d", fd);
  if (fd >= 0 && fd < (int) DIM (notify_table))
    {
      if (notify_table[fd].handler)
	{
	  notify_table[fd].handler (fd, notify_table[fd].value);
	  notify_table[fd].handler = NULL;
	  notify_table[fd].value = NULL;
        }
    }
  /* Then do the close.  */    
  return close (fd);
}


int
_gpgme_io_set_close_notify (int fd, void (*handler)(int, void*), void *value)
{
  assert (fd != -1);

  if (fd < 0 || fd >= (int) DIM (notify_table))
    return -1;
  DEBUG1 ("set notification for fd %d", fd);
  notify_table[fd].handler = handler;
  notify_table[fd].value = value;
  return 0;
}


int
_gpgme_io_set_nonblocking (int fd)
{
  int flags;

  flags = fcntl (fd, F_GETFL, 0);
  if (flags == -1)
    return -1;
  flags |= O_NONBLOCK;
  return fcntl (fd, F_SETFL, flags);
}


/* Returns 0 on success, -1 on error.  */
int
_gpgme_io_spawn (const char *path, char **argv,
		 struct spawn_fd_item_s *fd_child_list,
		 struct spawn_fd_item_s *fd_parent_list)
{
  pid_t pid;
  int i;
  int status, signo;

  pid = fork ();
  if (pid == -1) 
    return -1;

  if (!pid)
    {
      /* Intermediate child to prevent zombie processes.  */
      if ((pid = fork ()) == 0)
	{
	  /* Child.  */
	  int duped_stdin = 0;
	  int duped_stderr = 0;

	  /* First close all fds which will not be duped.  */
	  for (i=0; fd_child_list[i].fd != -1; i++)
	    if (fd_child_list[i].dup_to == -1)
	      close (fd_child_list[i].fd);

	  /* And now dup and close the rest.  */
	  for (i=0; fd_child_list[i].fd != -1; i++)
	    {
	      if (fd_child_list[i].dup_to != -1)
		{
		  if (dup2 (fd_child_list[i].fd,
			    fd_child_list[i].dup_to) == -1)
		    {
		      DEBUG1 ("dup2 failed in child: %s\n", strerror (errno));
		      _exit (8);
		    }
		  if (fd_child_list[i].dup_to == 0)
		    duped_stdin=1;
		  if (fd_child_list[i].dup_to == 2)
		    duped_stderr=1;
		  close (fd_child_list[i].fd);
		}
	    }
	  
	  if (!duped_stdin || !duped_stderr)
	    {
	      int fd = open ("/dev/null", O_RDWR);
	      if (fd == -1)
		{
		  DEBUG1 ("can't open `/dev/null': %s\n", strerror (errno));
		  _exit (8);
		}
	      /* Make sure that the process has a connected stdin.  */
	      if (!duped_stdin)
		{
		  if (dup2 (fd, 0) == -1)
		    {
		      DEBUG1("dup2(/dev/null, 0) failed: %s\n",
			     strerror (errno));
		      _exit (8);
		    }
		}
	      if (!duped_stderr)
		if (dup2 (fd, 2) == -1)
		  {
		    DEBUG1 ("dup2(dev/null, 2) failed: %s\n",
			    strerror (errno));
		    _exit (8);
		  }
	      close (fd);
	    }
    
	  execv ( path, argv );
	  /* Hmm: in that case we could write a special status code to the
	     status-pipe.  */
	  DEBUG1 ("exec of `%s' failed\n", path);
	  _exit (8);
	} /* End child.  */
      if (pid == -1)
	_exit (1);
      else
	_exit (0);
    }
    
  _gpgme_io_waitpid (pid, 1, &status, &signo);
  if (status)
    return -1;

  /* .dup_to is not used in the parent list.  */
  for (i = 0; fd_parent_list[i].fd != -1; i++)
    _gpgme_io_close (fd_parent_list[i].fd);

  return 0;
}


int
_gpgme_io_waitpid (int pid, int hang, int *r_status, int *r_signal)
{
  int status;

  *r_status = 0;
  *r_signal = 0;
  if (_gpgme_ath_waitpid (pid, &status, hang? 0 : WNOHANG) == pid)
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


int
_gpgme_io_kill (int pid, int hard)
{
  return kill (pid, hard ? SIGKILL : SIGTERM);
}


/*
 * Select on the list of fds.
 * Returns: -1 = error
 *           0 = timeout or nothing to select
 *          >0 = number of signaled fds
 */
int
_gpgme_io_select (struct io_select_fd_s *fds, size_t nfds, int nonblock)
{
  fd_set readfds;
  fd_set writefds;
  unsigned int i;
  int any, max_fd, n, count;
  struct timeval timeout = { 1, 0 }; /* Use a 1s timeout.  */
  void *dbg_help = NULL;

  FD_ZERO (&readfds);
  FD_ZERO (&writefds);
  max_fd = 0;
  if (nonblock)
    timeout.tv_sec = 0;

  DEBUG_BEGIN (dbg_help, 3, "gpgme:select on [ ");
  any = 0;
  for (i = 0; i < nfds; i++)
    {
      if (fds[i].fd == -1) 
	continue;
      if (fds[i].frozen)
	DEBUG_ADD1 (dbg_help, "f%d ", fds[i].fd);
      else if (fds[i].for_read)
	{
	  assert (!FD_ISSET (fds[i].fd, &readfds));
	  FD_SET (fds[i].fd, &readfds);
	  if (fds[i].fd > max_fd)
	    max_fd = fds[i].fd;
	  DEBUG_ADD1 (dbg_help, "r%d ", fds[i].fd);
	  any = 1;
        }
      else if (fds[i].for_write)
	{
	  assert (!FD_ISSET (fds[i].fd, &writefds));
	  FD_SET (fds[i].fd, &writefds);
	  if (fds[i].fd > max_fd)
	    max_fd = fds[i].fd;
	  DEBUG_ADD1 (dbg_help, "w%d ", fds[i].fd);
	  any = 1;
        }
      fds[i].signaled = 0;
    }
  DEBUG_END (dbg_help, "]"); 
  if (!any)
    return 0;

  do
    {
      count = _gpgme_ath_select (max_fd + 1, &readfds, &writefds, NULL,
				 &timeout);
    }
  while (count < 0 && errno == EINTR);
  if (count < 0)
    {
      int saved_errno = errno;
      DEBUG1 ("_gpgme_io_select failed: %s\n", strerror (errno));
      errno = saved_errno;
      return -1; /* error */
    }

  DEBUG_BEGIN (dbg_help, 3, "select OK [ ");
  if (DEBUG_ENABLED (dbg_help))
    {
      for (i = 0; i <= max_fd; i++)
	{
	  if (FD_ISSET (i, &readfds))
	    DEBUG_ADD1 (dbg_help, "r%d ", i);
	  if (FD_ISSET (i, &writefds))
	    DEBUG_ADD1 (dbg_help, "w%d ", i);
        }
      DEBUG_END (dbg_help, "]");
    }
    
  /* n is used to optimize it a little bit.  */
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
  return count;
}
