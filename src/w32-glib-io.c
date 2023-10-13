/* w32-glib-io.c - W32 Glib I/O functions
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2004, 2005 g10 Code GmbH
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
#include <string.h>
#include <assert.h>
#include <errno.h>
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
#include <glib.h>
#include <windows.h>
#include <io.h>

#include "util.h"
#include "priv-io.h"
#include "sema.h"
#include "debug.h"

#ifndef O_BINARY
#ifdef _O_BINARY
#define O_BINARY	_O_BINARY
#else
#define O_BINARY	0
#endif
#endif


/* This file is an ugly hack to get GPGME working with glib on Windows
   targets.  On Windows, you can not select() on file descriptors.
   The only way to check if there is something to read is to read
   something.  This means that GPGME can not let glib check for data
   without letting glib also handle the data on Windows targets.

   The ugly consequence is that we need to work on GIOChannels in
   GPGME, creating a glib dependency.  Also, we need to export an
   interface for the application to get at GPGME's GIOChannel.  There
   is no good way to abstract all this with callbacks, because the
   whole thing is also interconnected with the creation of pipes and
   child processes.

   The following rule applies only to this I/O backend:

   * ALL operations must use the user defined event loop.  GPGME can
   not anymore provide its own event loop.  This is mostly a sanity
   requirement: Although we have in theory all information we need to
   make the GPGME W32 code for select still work, it would be a big
   complication and require changes throughout GPGME.

   Eventually, we probably have to bite the bullet and make some
   really nice callback interfaces to let the user control all this at
   a per-context level.  */


#define MAX_SLAFD 256

static struct
{
  int used;

  /* If this is not -1, then it's a libc file descriptor.  */
  int fd;
  /* If fd is -1, this is the Windows socket handle.  */
  int socket;

  GIOChannel *chan;
  /* The boolean PRIMARY is true if this file descriptor caused the
     allocation of CHAN.  Only then should CHAN be destroyed when this
     FD is closed.  This, together with the fact that dup'ed file
     descriptors are closed before the file descriptors from which
     they are dup'ed are closed, ensures that CHAN is always valid,
     and shared among all file descriptors referring to the same
     underlying object.

     The logic behind this is that there is only one reason for us to
     dup file descriptors anyway: to allow simpler book-keeping of
     file descriptors shared between GPGME and libassuan, which both
     want to close something.  Using the same channel for these
     duplicates works just fine (and in fact, using different channels
     does not work because the W32 backend in glib does not support
     that: One would end up with several competing reader/writer
     threads.  */
  int primary;
} giochannel_table[MAX_SLAFD];


static GIOChannel *
find_channel (int fd)
{
  if (fd < 0 || fd >= MAX_SLAFD || !giochannel_table[fd].used)
    return NULL;

  return giochannel_table[fd].chan;
}


/* Returns the FD or -1 on resource limit.  */
int
new_dummy_channel_from_fd (int cfd)
{
  int idx;

  for (idx = 0; idx < MAX_SLAFD; idx++)
    if (! giochannel_table[idx].used)
      break;

  if (idx == MAX_SLAFD)
    {
      errno = EIO;
      return -1;
    }

  giochannel_table[idx].used = 1;
  giochannel_table[idx].chan = NULL;
  giochannel_table[idx].fd = cfd;
  giochannel_table[idx].socket = INVALID_SOCKET;
  giochannel_table[idx].primary = 1;

  return idx;
}


/* Returns the FD or -1 on resource limit.  */
int
new_channel_from_fd (int cfd)
{
  int idx;

  for (idx = 0; idx < MAX_SLAFD; idx++)
    if (! giochannel_table[idx].used)
      break;

  if (idx == MAX_SLAFD)
    {
      errno = EIO;
      return -1;
    }

  giochannel_table[idx].used = 1;
  giochannel_table[idx].chan = g_io_channel_win32_new_fd (cfd);
  giochannel_table[idx].fd = cfd;
  giochannel_table[idx].socket = INVALID_SOCKET;
  giochannel_table[idx].primary = 1;

  g_io_channel_set_encoding (giochannel_table[idx].chan, NULL, NULL);
  g_io_channel_set_buffered (giochannel_table[idx].chan, FALSE);

  return idx;
}


/* Returns the FD or -1 on resource limit.  */
int
new_channel_from_socket (int sock)
{
  int idx;

  for (idx = 0; idx < MAX_SLAFD; idx++)
    if (! giochannel_table[idx].used)
      break;

  if (idx == MAX_SLAFD)
    {
      errno = EIO;
      return -1;
    }

  giochannel_table[idx].used = 1;
  giochannel_table[idx].chan = g_io_channel_win32_new_socket (sock);
  giochannel_table[idx].fd = -1;
  giochannel_table[idx].socket = sock;
  giochannel_table[idx].primary = 1;

  g_io_channel_set_encoding (giochannel_table[idx].chan, NULL, NULL);
  g_io_channel_set_buffered (giochannel_table[idx].chan, FALSE);

  return idx;
}


/* Compatibility interface.  Obsolete.  */
void *
gpgme_get_giochannel (int fd)
{
  return find_channel (fd);
}


/* Look up the giochannel for "file descriptor" FD.  */
void *
gpgme_get_fdptr (int fd)
{
  return find_channel (fd);
}


/* Write the printable version of FD to the buffer BUF of length
   BUFLEN.  The printable version is the representation on the command
   line that the child process expects.  */
int
_gpgme_io_fd2str (char *buf, int buflen, int fd)
{
  HANDLE hndl;

  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_fd2str", fd, "fd=%d", fd);
  if (giochannel_table[fd].fd != -1)
    hndl = (HANDLE) _get_osfhandle (giochannel_table[fd].fd);
  else
    hndl = (HANDLE) giochannel_table[fd].socket;

  TRACE_SUC ("syshd=%p", hndl);

  return snprintf (buf, buflen, "%d", (int) hndl);
}


void
_gpgme_io_subsystem_init (void)
{
}


static struct
{
  _gpgme_close_notify_handler_t handler;
  void *value;
} notify_table[MAX_SLAFD];


int
_gpgme_io_read (int fd, void *buffer, size_t count)
{
  int saved_errno = 0;
  gsize nread;
  GIOChannel *chan;
  GIOStatus status;
  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_read", fd,
	      "buffer=%p, count=%u", buffer, count);

  chan = find_channel (fd);
  if (!chan)
    {
      TRACE_LOG ("no channel registered");
      errno = EINVAL;
      return TRACE_SYSRES (-1);
    }
  TRACE_LOG  ("channel %p", chan);

  {
    GError *err = NULL;
    status = g_io_channel_read_chars (chan, (gchar *) buffer,
				      count, &nread, &err);
    if (err)
      {
	TRACE_LOG  ("status %i, err %s", status, err->message);
	g_error_free (err);
      }
  }

  if (status == G_IO_STATUS_EOF)
    nread = 0;
  else if (status == G_IO_STATUS_AGAIN)
    {
      nread = -1;
      saved_errno = EAGAIN;
    }
  else if (status != G_IO_STATUS_NORMAL)
    {
      TRACE_LOG  ("status %d", status);
      nread = -1;
      saved_errno = EIO;
    }

  if (nread != 0 && nread != -1)
    TRACE_LOGBUFX (buffer, nread);

  errno = saved_errno;
  return TRACE_SYSRES (nread);
}


int
_gpgme_io_write (int fd, const void *buffer, size_t count)
{
  int saved_errno = 0;
  gsize nwritten;
  GIOChannel *chan;
  GIOStatus status;
  GError *err = NULL;

  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_write", fd,
	      "buffer=%p, count=%u", buffer, count);
  TRACE_LOGBUFX (buffer, count);

  chan = find_channel (fd);
  if (!chan)
    {
      TRACE_LOG ("fd=%d: no channel registered");
      errno = EINVAL;
      return -1;
    }

  status = g_io_channel_write_chars (chan, (gchar *) buffer, count,
				     &nwritten, &err);
  if (err)
    {
      TRACE_LOG  ("write error: %s", err->message);
      g_error_free (err);
    }

  if (status == G_IO_STATUS_AGAIN)
    {
      nwritten = -1;
      saved_errno = EAGAIN;
    }
  else if (status != G_IO_STATUS_NORMAL)
    {
      nwritten = -1;
      saved_errno = EIO;
    }
  errno = saved_errno;

  return TRACE_SYSRES (nwritten);
}


int
_gpgme_io_pipe (int filedes[2], int inherit_idx)
{
  int fds[2];

  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_pipe", filedes,
	      "inherit_idx=%i (GPGME uses it for %s)",
	      inherit_idx, inherit_idx ? "reading" : "writing");

#define PIPEBUF_SIZE  4096
  if (_pipe (fds, PIPEBUF_SIZE, O_NOINHERIT | O_BINARY) == -1)
    return TRACE_SYSRES (-1);

  /* Make one end inheritable. */
  if (inherit_idx == 0)
    {
      int new_read;

      new_read = _dup (fds[0]);
      _close (fds[0]);
      fds[0] = new_read;

      if (new_read < 0)
	{
	  _close (fds[1]);
	  return TRACE_SYSRES (-1);
	}
    }
  else if (inherit_idx == 1)
    {
      int new_write;

      new_write = _dup (fds[1]);
      _close (fds[1]);
      fds[1] = new_write;

      if (new_write < 0)
	{
	  _close (fds[0]);
	  return TRACE_SYSRES (-1);
	}
    }

  /* For _gpgme_io_close.  */
  filedes[inherit_idx] = new_dummy_channel_from_fd (fds[inherit_idx]);
  if (filedes[inherit_idx] < 0)
    {
      int saved_errno = errno;

      _close (fds[0]);
      _close (fds[1]);
      errno = saved_errno;
      return TRACE_SYSRES (-1);
    }

  /* Now we have a pipe with the correct end inheritable.  The other end
     should have a giochannel.  */
  filedes[1 - inherit_idx] = new_channel_from_fd (fds[1 - inherit_idx]);
  if (filedes[1 - inherit_idx] < 0)
    {
      int saved_errno = errno;

      _gpgme_io_close (fds[inherit_idx]);
      _close (fds[1 - inherit_idx]);
      errno = saved_errno;
      return TRACE_SYSRES (-1);
    }

  TRACE_SUC ("read=0x%x/%p, write=0x%x/%p, channel=%p",
	     filedes[0],
	     (HANDLE) _get_osfhandle (giochannel_table[filedes[0]].fd),
	     filedes[1],
	     (HANDLE) _get_osfhandle (giochannel_table[filedes[1]].fd),
	     giochannel_table[1 - inherit_idx].chan);
  return 0;
}


int
_gpgme_io_close (int fd)
{
  TRACE_BEG (DEBUG_SYSIO, "_gpgme_io_close", fd, "");

  if (fd < 0 || fd >= MAX_SLAFD)
    {
      errno = EBADF;
      return TRACE_SYSRES (-1);
    }

  assert (giochannel_table[fd].used);

  /* First call the notify handler.  */
  if (notify_table[fd].handler)
    {
      notify_table[fd].handler (fd, notify_table[fd].value);
      notify_table[fd].handler = NULL;
      notify_table[fd].value = NULL;
    }

  /* Then do the close.  */
  if (giochannel_table[fd].chan)
    {
      if (giochannel_table[fd].primary)
	g_io_channel_shutdown (giochannel_table[fd].chan, 1, NULL);

      g_io_channel_unref (giochannel_table[fd].chan);
    }
  else
    {
      /* Dummy entry, just close.  */
      assert (giochannel_table[fd].fd != -1);
      _close (giochannel_table[fd].fd);
    }

  giochannel_table[fd].used = 0;
  giochannel_table[fd].fd = -1;
  giochannel_table[fd].socket = INVALID_SOCKET;
  giochannel_table[fd].chan = NULL;
  giochannel_table[fd].primary = 0;

  TRACE_SUC ("");
  return 0;
}


int
_gpgme_io_set_close_notify (int fd, _gpgme_close_notify_handler_t handler,
			    void *value)
{
  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_set_close_notify", fd,
	      "close_handler=%p/%p", handler, value);

  assert (fd != -1);

  if (fd < 0 || fd >= (int) DIM (notify_table))
    {
      errno = EINVAL;
      return TRACE_SYSRES (-1);
    }
  notify_table[fd].handler = handler;
  notify_table[fd].value = value;
  return TRACE_SYSRES (0);
}


int
_gpgme_io_set_nonblocking (int fd)
{
  GIOChannel *chan;
  GIOStatus status;

  TRACE_BEG (DEBUG_SYSIO, "_gpgme_io_set_nonblocking", fd, "");

  chan = find_channel (fd);
  if (!chan)
    {
      errno = EIO;
      return TRACE_SYSRES (-1);
    }

  status = g_io_channel_set_flags (chan,
				   g_io_channel_get_flags (chan) |
				   G_IO_FLAG_NONBLOCK, NULL);

  if (status != G_IO_STATUS_NORMAL)
    {
#if 0
      /* glib 1.9.2 does not implement set_flags and returns an
	 error.  */
      errno = EIO;
      return TRACE_SYSRES (-1);
#else
      TRACE_LOG  ("g_io_channel_set_flags failed: status=%d (ignored)",
		  status);
#endif
    }

  return TRACE_SYSRES (0);
}


static char *
build_commandline (char **argv)
{
  int i;
  int n = 0;
  char *buf;
  char *p;

  /* We have to quote some things because under Windows the program
     parses the commandline and does some unquoting.  We enclose the
     whole argument in double-quotes, and escape literal double-quotes
     as well as backslashes with a backslash.  We end up with a
     trailing space at the end of the line, but that is harmless.  */
  for (i = 0; argv[i]; i++)
    {
      p = argv[i];
      /* The leading double-quote.  */
      n++;
      while (*p)
	{
	  /* An extra one for each literal that must be escaped.  */
	  if (*p == '\\' || *p == '"')
	    n++;
	  n++;
	  p++;
	}
      /* The trailing double-quote and the delimiter.  */
      n += 2;
    }
  /* And a trailing zero.  */
  n++;

  buf = p = malloc (n);
  if (!buf)
    return NULL;
  for (i = 0; argv[i]; i++)
    {
      char *argvp = argv[i];

      *(p++) = '"';
      while (*argvp)
	{
	  if (*argvp == '\\' || *argvp == '"')
	    *(p++) = '\\';
	  *(p++) = *(argvp++);
	}
      *(p++) = '"';
      *(p++) = ' ';
    }
  *(p++) = 0;

  return buf;
}


int
_gpgme_io_spawn (const char *path, char * const argv[], unsigned int flags,
		 struct spawn_fd_item_s *fd_list,
		 void (*atfork) (void *opaque, int reserved),
		 void *atforkvalue, pid_t *r_pid)
{
  SECURITY_ATTRIBUTES sec_attr;
  PROCESS_INFORMATION pi =
    {
      NULL,      /* returns process handle */
      0,         /* returns primary thread handle */
      0,         /* returns pid */
      0          /* returns tid */
    };
  STARTUPINFO si;
  int cr_flags = (CREATE_DEFAULT_ERROR_MODE
                  | GetPriorityClass (GetCurrentProcess ()));
  int i;
  char **args;
  char *arg_string;
  /* FIXME.  */
  int debug_me = 0;
  int tmp_fd;
  char *tmp_name;

  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_spawn", path,
	      "path=%s", path);
  i = 0;
  while (argv[i])
    {
      TRACE_LOG  ("argv[%2i] = %s", i, argv[i]);
      i++;
    }

  /* We do not inherit any handles by default, and just insert those
     handles we want the child to have afterwards.  But some handle
     values occur on the command line, and we need to move
     stdin/out/err to the right location.  So we use a wrapper program
     which gets the information from a temporary file.  */
  if (_gpgme_mkstemp (&tmp_fd, &tmp_name) < 0)
    {
      TRACE_LOG  ("_gpgme_mkstemp failed: %s", strerror (errno));
      return TRACE_SYSRES (-1);
    }
  TRACE_LOG  ("tmp_name = %s", tmp_name);

  args = calloc (2 + i + 1, sizeof (*args));
  args[0] = (char *) _gpgme_get_w32spawn_path ();
  args[1] = tmp_name;
  args[2] = path;
  memcpy (&args[3], &argv[1], i * sizeof (*args));

  memset (&sec_attr, 0, sizeof sec_attr);
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = FALSE;

  arg_string = build_commandline (args);
  free (args);
  if (!arg_string)
    {
      close (tmp_fd);
      DeleteFile (tmp_name);
      return TRACE_SYSRES (-1);
    }

  memset (&si, 0, sizeof si);
  si.cb = sizeof (si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = debug_me ? SW_SHOW : SW_HIDE;
  si.hStdInput = INVALID_HANDLE_VALUE;
  si.hStdOutput = INVALID_HANDLE_VALUE;
  si.hStdError = INVALID_HANDLE_VALUE;

  cr_flags |= CREATE_SUSPENDED;
  if ((flags & IOSPAWN_FLAG_DETACHED))
    cr_flags |= DETACHED_PROCESS;
  if (!CreateProcessA (_gpgme_get_w32spawn_path (),
		       arg_string,
		       &sec_attr,     /* process security attributes */
		       &sec_attr,     /* thread security attributes */
		       FALSE,         /* inherit handles */
		       cr_flags,      /* creation flags */
		       NULL,          /* environment */
		       NULL,          /* use current drive/directory */
		       &si,           /* startup information */
		       &pi))          /* returns process information */
    {
      TRACE_LOG  ("CreateProcess failed: ec=%d", (int) GetLastError ());
      free (arg_string);
      close (tmp_fd);
      DeleteFile (tmp_name);

      /* FIXME: Should translate the error code.  */
      errno = EIO;
      return TRACE_SYSRES (-1);
    }

  free (arg_string);

  if (flags & IOSPAWN_FLAG_ALLOW_SET_FG)
    _gpgme_allow_set_foreground_window ((pid_t)pi.dwProcessId);

  /* Insert the inherited handles.  */
  for (i = 0; fd_list[i].fd != -1; i++)
    {
      HANDLE hd;

      /* Make it inheritable for the wrapper process.  */
      if (!DuplicateHandle (GetCurrentProcess(),
			    _get_osfhandle (giochannel_table[fd_list[i].fd].fd),
			    pi.hProcess, &hd, 0, TRUE, DUPLICATE_SAME_ACCESS))
	{
	  TRACE_LOG  ("DuplicateHandle failed: ec=%d", (int) GetLastError ());
	  TerminateProcess (pi.hProcess, 0);
	  /* Just in case TerminateProcess didn't work, let the
	     process fail on its own.  */
	  ResumeThread (pi.hThread);
	  CloseHandle (pi.hThread);
	  CloseHandle (pi.hProcess);

	  close (tmp_fd);
	  DeleteFile (tmp_name);

	  /* FIXME: Should translate the error code.  */
	  errno = EIO;
	  return TRACE_SYSRES (-1);
        }
      /* Return the child name of this handle.  */
      fd_list[i].peer_name = (int) hd;
    }

  /* Write the handle translation information to the temporary
     file.  */
  {
    /* Hold roughly MAX_TRANS quadruplets of 64 bit numbers in hex
       notation: "0xFEDCBA9876543210" with an extra white space after
       every quadruplet.  10*(19*4 + 1) - 1 = 769.  This plans ahead
       for a time when a HANDLE is 64 bit.  */
#define BUFFER_MAX 800
    char line[BUFFER_MAX + 1];
    int res;
    int written;
    size_t len;

    if ((flags & IOSPAWN_FLAG_ALLOW_SET_FG))
      strcpy (line, "~1 \n");
    else
      strcpy (line, "\n");
    for (i = 0; fd_list[i].fd != -1; i++)
      {
	/* Strip the newline.  */
	len = strlen (line) - 1;

	/* Format is: Local name, stdin/stdout/stderr, peer name, argv idx.  */
	snprintf (&line[len], BUFFER_MAX - len, "0x%x %d 0x%x %d  \n",
		  fd_list[i].fd, fd_list[i].dup_to,
		  fd_list[i].peer_name, fd_list[i].arg_loc);
	/* Rather safe than sorry.  */
	line[BUFFER_MAX - 1] = '\n';
	line[BUFFER_MAX] = '\0';
      }
    len = strlen (line);
    written = 0;
    do
      {
	res = write (tmp_fd, &line[written], len - written);
	if (res > 0)
	  written += res;
      }
    while (res > 0 || (res < 0 && errno == EAGAIN));
  }
  close (tmp_fd);
  /* The temporary file is deleted by the gpgme-w32spawn process
     (hopefully).  */

  TRACE_LOG  ("CreateProcess ready: hProcess=%p, hThread=%p, "
	      "dwProcessID=%d, dwThreadId=%d",
	      pi.hProcess, pi.hThread,
	      (int) pi.dwProcessId, (int) pi.dwThreadId);

  if (r_pid)
    *r_pid = (pid_t)pi.dwProcessId;

  if (ResumeThread (pi.hThread) < 0)
    TRACE_LOG  ("ResumeThread failed: ec=%d", (int) GetLastError ());

  if (!CloseHandle (pi.hThread))
    TRACE_LOG  ("CloseHandle of thread failed: ec=%d",
		(int) GetLastError ());

  TRACE_LOG  ("process=%p", pi.hProcess);

  /* We don't need to wait for the process.  */
  if (!CloseHandle (pi.hProcess))
    TRACE_LOG  ("CloseHandle of process failed: ec=%d",
		(int) GetLastError ());

  if (! (flags & IOSPAWN_FLAG_NOCLOSE))
    {
      for (i = 0; fd_list[i].fd != -1; i++)
	_gpgme_io_close (fd_list[i].fd);
    }

  for (i = 0; fd_list[i].fd != -1; i++)
    if (fd_list[i].dup_to == -1)
      TRACE_LOG  ("fd[%i] = 0x%x -> 0x%x", i, fd_list[i].fd,
		  fd_list[i].peer_name);
    else
      TRACE_LOG  ("fd[%i] = 0x%x -> 0x%x (std%s)", i, fd_list[i].fd,
		  fd_list[i].peer_name, (fd_list[i].dup_to == 0) ? "in" :
		  ((fd_list[i].dup_to == 1) ? "out" : "err"));

  return TRACE_SYSRES (0);
}


/* Select on the list of fds.  Returns: -1 = error, 0 = timeout or
   nothing to select, > 0 = number of signaled fds.  */
int
_gpgme_io_select (struct io_select_fd_s *fds, size_t nfds, int nonblock)
{
  int npollfds;
  GPollFD *pollfds;
  int *pollfds_map;
  int i;
  int j;
  int any;
  int n;
  int count;
  /* Use a 1s timeout.  */
  int timeout = 1000;
  void *dbg_help = NULL;
  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_select", fds,
	      "nfds=%u, nonblock=%u", nfds, nonblock);

  if (nonblock)
    timeout = 0;

  pollfds = calloc (nfds, sizeof *pollfds);
  if (!pollfds)
    return -1;
  pollfds_map = calloc (nfds, sizeof *pollfds_map);
  if (!pollfds_map)
    {
      free (pollfds);
      return -1;
    }
  npollfds = 0;

  TRACE_SEQ (dbg_help, "select on [ ");
  any = 0;
  for (i = 0; i < nfds; i++)
    {
      GIOChannel *chan = NULL;

      if (fds[i].fd == -1)
	continue;

      if ((fds[i].for_read || fds[i].for_write)
          && !(chan = find_channel (fds[i].fd)))
        {
          TRACE_ADD1 (dbg_help, "[BAD0x%x ", fds[i].fd);
          TRACE_END (dbg_help, "]");
          assert (!"see log file");
        }
      else if (fds[i].for_read )
	{
          assert(chan);
          g_io_channel_win32_make_pollfd (chan, G_IO_IN, pollfds + npollfds);
          pollfds_map[npollfds] = i;
	  TRACE_ADD2 (dbg_help, "r0x%x<%d> ", fds[i].fd, pollfds[npollfds].fd);
          npollfds++;
	  any = 1;
        }
      else if (fds[i].for_write)
	{
          assert(chan);
          g_io_channel_win32_make_pollfd (chan, G_IO_OUT, pollfds + npollfds);
          pollfds_map[npollfds] = i;
	  TRACE_ADD2 (dbg_help, "w0x%x<%d> ", fds[i].fd, pollfds[npollfds].fd);
          npollfds++;
	  any = 1;
        }
      fds[i].signaled = 0;
    }
  TRACE_END (dbg_help, "]");
  if (!any)
    {
      count = 0;
      goto leave;
    }


  count = g_io_channel_win32_poll (pollfds, npollfds, timeout);
  if (count < 0)
    {
      int saved_errno = errno;
      errno = saved_errno;
      goto leave;
    }

  TRACE_SEQ (dbg_help, "select OK [ ");
  if (TRACE_ENABLED (dbg_help))
    {
      for (i = 0; i < npollfds; i++)
	{
	  if ((pollfds[i].revents & G_IO_IN))
	    TRACE_ADD1 (dbg_help, "r0x%x ", fds[pollfds_map[i]].fd);
          if ((pollfds[i].revents & G_IO_OUT))
            TRACE_ADD1 (dbg_help, "w0x%x ", fds[pollfds_map[i]].fd);
        }
      TRACE_END (dbg_help, "]");
    }

  /* COUNT is used to stop the loop as soon as possible.  */
  for (n = count, i = 0; i < npollfds && n; i++)
    {
      j = pollfds_map[i];
      assert (j >= 0 && j < nfds);
      if (fds[j].fd == -1)
	;
      else if (fds[j].for_read)
	{
	  if ((pollfds[i].revents & G_IO_IN))
	    {
	      fds[j].signaled = 1;
	      n--;
            }
        }
      else if (fds[j].for_write)
	{
	  if ((pollfds[i].revents & G_IO_OUT))
	    {
	      fds[j].signaled = 1;
	      n--;
            }
        }
    }

leave:
  free (pollfds);
  free (pollfds_map);
  return TRACE_SYSRES (count);
}


int
_gpgme_io_dup (int fd)
{
  int newfd;
  GIOChannel *chan;

  TRACE_BEG (DEBUG_SYSIO, "_gpgme_io_dup", fd, "");

  if (fd < 0 || fd >= MAX_SLAFD || !giochannel_table[fd].used)
    {
      errno = EINVAL;
      return TRACE_SYSRES (-1);
    }

  for (newfd = 0; newfd < MAX_SLAFD; newfd++)
    if (! giochannel_table[newfd].used)
      break;
  if (newfd == MAX_SLAFD)
    {
      errno = EIO;
      return TRACE_SYSRES (-1);
    }

  chan = giochannel_table[fd].chan;
  g_io_channel_ref (chan);
  giochannel_table[newfd].used = 1;
  giochannel_table[newfd].chan = chan;
  giochannel_table[newfd].fd = -1;
  giochannel_table[newfd].socket = INVALID_SOCKET;
  giochannel_table[newfd].primary = 0;

  return TRACE_SYSRES (newfd);
}





static int
wsa2errno (int err)
{
  switch (err)
    {
    case WSAENOTSOCK:
      return EINVAL;
    case WSAEWOULDBLOCK:
      return EAGAIN;
    case ERROR_BROKEN_PIPE:
      return EPIPE;
    case WSANOTINITIALISED:
      return ENOSYS;
    default:
      return EIO;
    }
}


int
_gpgme_io_socket (int domain, int type, int proto)
{
  int res;
  int fd;

  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_socket", domain,
	      "type=%i, protp=%i", type, proto);

  res = socket (domain, type, proto);
  if (res == INVALID_SOCKET)
    {
      errno = wsa2errno (WSAGetLastError ());
      return TRACE_SYSRES (-1);
    }

  fd = new_channel_from_socket (res);
  if (fd < 0)
    {
      int saved_errno = errno;
      closesocket (res);
      errno = saved_errno;
      return TRACE_SYSRES (-1);
    }

  TRACE_SUC ("fd=%i, socket=0x%x", fd, res);

  return fd;
}


int
_gpgme_io_connect (int fd, struct sockaddr *addr, int addrlen)
{
  GIOChannel *chan;
  int sockfd;
  int res;
  GIOFlags flags;
  GIOStatus status;
  GError *err = NULL;

  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_connect", fd,
	      "addr=%p, addrlen=%i", addr, addrlen);

  chan = find_channel (fd);
  if (! chan)
    {
      errno = EINVAL;
      return TRACE_SYSRES (-1);
    }

  flags = g_io_channel_get_flags (chan);
  if (flags & G_IO_FLAG_NONBLOCK)
    {
      status = g_io_channel_set_flags (chan, flags & ~G_IO_FLAG_NONBLOCK, &err);
      if (err)
	{
	  TRACE_LOG  ("setting flags error: %s", err->message);
	  g_error_free (err);
	  err = NULL;
	}
      if (status != G_IO_STATUS_NORMAL)
	{
	  errno = EIO;
	  return TRACE_SYSRES (-1);
	}
    }

  sockfd = giochannel_table[fd].socket;
  if (sockfd == INVALID_SOCKET)
    {
      errno = EINVAL;
      return TRACE_SYSRES (-1);
    }

  TRACE_LOG  ("connect socket fd=%d", sockfd);
  res = connect (sockfd, addr, addrlen);

  /* FIXME: Error ignored here.  */
  if (! (flags & G_IO_FLAG_NONBLOCK))
    g_io_channel_set_flags (chan, flags, NULL);

  if (res)
    {
      TRACE_LOG  ("connect failed: %i %i", res, WSAGetLastError ());

      errno = wsa2errno (WSAGetLastError ());
      return TRACE_SYSRES (-1);
    }

  TRACE_SUC ("");

  return 0;
}
