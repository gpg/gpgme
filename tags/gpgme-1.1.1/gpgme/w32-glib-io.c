/* w32-glib-io.c - W32 Glib I/O functions
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2004, 2005 g10 Code GmbH

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

GIOChannel *giochannel_table[MAX_SLAFD];


static GIOChannel *
find_channel (int fd, int create)
{
  if (fd < 0 || fd >= MAX_SLAFD)
    return NULL;

  if (create && !giochannel_table[fd])
    {
      giochannel_table[fd] = g_io_channel_win32_new_fd (fd);
      g_io_channel_set_encoding (giochannel_table[fd], NULL, NULL);
      g_io_channel_set_buffered (giochannel_table[fd], FALSE);
    }

  return giochannel_table[fd];
}

/* Look up the giochannel for "file descriptor" FD.  */
GIOChannel *
gpgme_get_giochannel (int fd)
{
  return find_channel (fd, 0);
}


/* Write the printable version of FD to the buffer BUF of length
   BUFLEN.  The printable version is the representation on the command
   line that the child process expects.  */
int
_gpgme_io_fd2str (char *buf, int buflen, int fd)
{
  return snprintf (buf, buflen, "%ld", (long) _get_osfhandle (fd));
}


void
_gpgme_io_subsystem_init (void)
{
}


static struct
{
  void (*handler) (int,void*);
  void *value;
} notify_table[MAX_SLAFD];

int
_gpgme_io_read (int fd, void *buffer, size_t count)
{
  int saved_errno = 0;
  gsize nread;
  GIOChannel *chan;
  GIOStatus status;

  DEBUG2 ("fd %d: about to read %d bytes\n", fd, (int) count);

  chan = find_channel (fd, 0);
  if (!chan)
    {
      DEBUG1 ("fd %d: no channel registered\n", fd);
      errno = EINVAL;
      return -1;
    }
  DEBUG2 ("fd %d: channel %p\n", fd, chan);

  {
    GError *err = NULL;
    status = g_io_channel_read_chars (chan, (gchar *) buffer,
				      count, &nread, &err);
    if (err)
      {
	DEBUG3 ("fd %d: status %i, err %s\n", fd, status, err->message);
	g_error_free (err);
      }
  }

  if (status == G_IO_STATUS_EOF)
    nread = 0;
  else if (status != G_IO_STATUS_NORMAL)
    {
      DEBUG2 ("fd %d: status %d\n", fd, status);
      nread = -1;
      saved_errno = EIO;
    }

  DEBUG2 ("fd %d: got %d bytes\n", fd, nread);
  if (nread > 0)
    _gpgme_debug (2, "fd %d: got `%.*s'\n", fd, nread, buffer);

  errno = saved_errno;
  return nread;
}


int
_gpgme_io_write (int fd, const void *buffer, size_t count)
{
  int saved_errno = 0;
  gsize nwritten;
  GIOChannel *chan;
  GIOStatus status;

  DEBUG2 ("fd %d: about to write %d bytes\n", fd, (int) count);
  _gpgme_debug (2, "fd %d: write `%.*s'\n", fd, (int) count, buffer);

  chan = find_channel (fd, 0);
  if (!chan)
    {
      DEBUG1 ("fd %d: no channel registered\n", fd);
      errno = EINVAL;
      return -1;
    }

  status = g_io_channel_write_chars (chan, (gchar *) buffer, count,
				     &nwritten, NULL);
  if (status != G_IO_STATUS_NORMAL)
    {
      nwritten = -1;
      saved_errno = EIO;
    }
  DEBUG2 ("fd %d:          wrote %d bytes\n", fd, (int) nwritten);
  errno = saved_errno;
  return nwritten;
}


int
_gpgme_io_pipe (int filedes[2], int inherit_idx)
{
  GIOChannel *chan;

#define PIPEBUF_SIZE  4096
  if (_pipe (filedes, PIPEBUF_SIZE, O_NOINHERIT | O_BINARY) == -1)
    return -1;

  /* Make one end inheritable. */
  if (inherit_idx == 0)
    {
      int new_read;

      new_read = _dup (filedes[0]);
      _close (filedes[0]);
      filedes[0] = new_read;

      if (new_read < 0)
	{
	  _close (filedes[1]);
	  return -1;
	}
    }
  else if (inherit_idx == 1)
    {
      int new_write;

      new_write = _dup (filedes[1]);
      _close (filedes[1]);
      filedes[1] = new_write;

      if (new_write < 0)
	{
	  _close (filedes[0]);
	  return -1;
	}
    }

  /* Now we have a pipe with the right end inheritable.  The other end
     should have a giochannel.  */
  chan = find_channel (filedes[1 - inherit_idx], 1);
  if (!chan)
    {
      DEBUG2 ("channel creation for %d failed: ec=%d\n",
	      filedes[1 - inherit_idx], errno);
      _close (filedes[0]);
      _close (filedes[1]);
      return -1;
    }

  DEBUG5 ("CreatePipe %d (%p) %d (%p) inherit=%p\n",
	  filedes[0], (HANDLE) _get_osfhandle (filedes[0]),
	  filedes[1], (HANDLE) _get_osfhandle (filedes[1]),
	  chan);
  return 0;
}


int
_gpgme_io_close (int fd)
{
  GIOChannel *chan;

  if (fd < 0 || fd >= MAX_SLAFD)
    {
      errno = EBADF;
      return -1;
    }

  /* First call the notify handler.  */
  DEBUG1 ("closing fd %d", fd);
  if (notify_table[fd].handler)
    {
      notify_table[fd].handler (fd, notify_table[fd].value);
      notify_table[fd].handler = NULL;
      notify_table[fd].value = NULL;
    }

  /* Then do the close.  */    
  chan = giochannel_table[fd];
  if (chan)
    {
      g_io_channel_shutdown (chan, 1, NULL);
      g_io_channel_unref (chan);
      giochannel_table[fd] = NULL;
    }
  else
    _close (fd);


  return 0;
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
  GIOChannel *chan;
  GIOStatus status;
 
  chan = find_channel (fd, 0);
  if (!chan)
    {
      DEBUG1 ("set nonblocking for fd %d failed: channel not found", fd);
      errno = EIO;
      return -1;
    }

   status = g_io_channel_set_flags (chan,
				   g_io_channel_get_flags (chan) |
				   G_IO_FLAG_NONBLOCK, NULL);
  if (status != G_IO_STATUS_NORMAL)
    {
      /* glib 1.9.2 does not implement set_flags and returns an error. */
      DEBUG2 ("set nonblocking for fd %d failed: status=%d - ignored",
              fd, status);
/*       errno = EIO; */
/*       return -1; */
    }

  return 0;
}


static char *
build_commandline ( char **argv )
{
  int i, n = 0;
  char *buf, *p;
  
  /* FIXME: we have to quote some things because under Windows the
   * program parses the commandline and does some unquoting.  For now
   * we only do very basic quoting to the first argument because this
   * one often contains a space (e.g. C:\\Program Files\GNU\GnuPG\gpg.exe) 
   * and we would produce an invalid line in that case.  */
  for (i=0; argv[i]; i++)
    n += strlen (argv[i]) + 2 + 1; /* 2 extra bytes for possible quoting */
  buf = p = malloc (n);
  if ( !buf )
    return NULL;
  *buf = 0;
  if ( argv[0] )
    {
      if (strpbrk (argv[0], " \t"))
        p = stpcpy (stpcpy (stpcpy (p, "\""), argv[0]), "\"");
      else
        p = stpcpy (p, argv[0]);
      for (i = 1; argv[i]; i++)
        {
          if (!*argv[i])
            p = stpcpy (p, " \"\"");
          else
            p = stpcpy (stpcpy (p, " "), argv[i]);
        }
    }
  
  return buf;
}


int
_gpgme_io_spawn ( const char *path, char **argv,
                  struct spawn_fd_item_s *fd_child_list,
                  struct spawn_fd_item_s *fd_parent_list )
{
    SECURITY_ATTRIBUTES sec_attr;
    PROCESS_INFORMATION pi = {
        NULL,      /* returns process handle */
        0,         /* returns primary thread handle */
        0,         /* returns pid */
        0         /* returns tid */
    };
    STARTUPINFO si;
    char *envblock = NULL;
    int cr_flags = CREATE_DEFAULT_ERROR_MODE
                 | GetPriorityClass (GetCurrentProcess ());
    int i;
    char *arg_string;
    int duped_stdin = 0;
    int duped_stderr = 0;
    HANDLE hnul = INVALID_HANDLE_VALUE;
    /* FIXME.  */
    int debug_me = 0;

    memset (&sec_attr, 0, sizeof sec_attr);
    sec_attr.nLength = sizeof sec_attr;
    sec_attr.bInheritHandle = FALSE;

    arg_string = build_commandline (argv);
    if (!arg_string )
        return -1; 

    memset (&si, 0, sizeof si);
    si.cb = sizeof (si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = debug_me? SW_SHOW : SW_HIDE;
    si.hStdInput = GetStdHandle (STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle (STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle (STD_ERROR_HANDLE);

    for (i=0; fd_child_list[i].fd != -1; i++ ) {
        if (fd_child_list[i].dup_to == 0 ) {
            si.hStdInput = (HANDLE) _get_osfhandle (fd_child_list[i].fd);
            DEBUG2 ("using %d (%p) for stdin", fd_child_list[i].fd,
		    _get_osfhandle (fd_child_list[i].fd));
            duped_stdin=1;
        }
        else if (fd_child_list[i].dup_to == 1 ) {
            si.hStdOutput = (HANDLE) _get_osfhandle (fd_child_list[i].fd);
            DEBUG2 ("using %d (%p) for stdout", fd_child_list[i].fd,
		    _get_osfhandle (fd_child_list[i].fd));
        }
        else if (fd_child_list[i].dup_to == 2 ) {
            si.hStdError = (HANDLE) _get_osfhandle (fd_child_list[i].fd);
            DEBUG2 ("using %d (%p) for stderr", fd_child_list[i].fd,
		    _get_osfhandle (fd_child_list[i].fd));
            duped_stderr = 1;
        }
    }

    if( !duped_stdin || !duped_stderr ) {
        SECURITY_ATTRIBUTES sa;

        memset (&sa, 0, sizeof sa );
        sa.nLength = sizeof sa;
        sa.bInheritHandle = TRUE;
        hnul = CreateFile ( "nul",
                            GENERIC_READ|GENERIC_WRITE,
                            FILE_SHARE_READ|FILE_SHARE_WRITE,
                            &sa,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL );
        if ( hnul == INVALID_HANDLE_VALUE ) {
            DEBUG1 ("can't open `nul': ec=%d\n", (int)GetLastError ());
            free (arg_string);
            return -1;
        }
        /* Make sure that the process has a connected stdin */
        if ( !duped_stdin ) {
            si.hStdInput = hnul;
            DEBUG1 ("using %d for dummy stdin", (int)hnul );
        }
        /* We normally don't want all the normal output */
        if ( !duped_stderr ) {
            si.hStdError = hnul;
            DEBUG1 ("using %d for dummy stderr", (int)hnul );
        }
    }

    DEBUG2 ("CreateProcess, path=`%s' args=`%s'", path, arg_string);
    cr_flags |= CREATE_SUSPENDED; 
    if ( !CreateProcessA (path,
                          arg_string,
                          &sec_attr,     /* process security attributes */
                          &sec_attr,     /* thread security attributes */
                          TRUE,          /* inherit handles */
                          cr_flags,      /* creation flags */
                          envblock,      /* environment */
                          NULL,          /* use current drive/directory */
                          &si,           /* startup information */
                          &pi            /* returns process information */
        ) ) {
        DEBUG1 ("CreateProcess failed: ec=%d\n", (int) GetLastError ());
        free (arg_string);
        return -1;
    }

    /* Close the /dev/nul handle if used. */
    if (hnul != INVALID_HANDLE_VALUE ) {
        if ( !CloseHandle ( hnul ) )
            DEBUG1 ("CloseHandle(hnul) failed: ec=%d\n", (int)GetLastError());
    }

    /* Close the other ends of the pipes. */
    for (i = 0; fd_parent_list[i].fd != -1; i++)
      _gpgme_io_close (fd_parent_list[i].fd);

    DEBUG4 ("CreateProcess ready\n"
            "-   hProcess=%p  hThread=%p\n"
            "-   dwProcessID=%d dwThreadId=%d\n",
            pi.hProcess, pi.hThread, 
            (int) pi.dwProcessId, (int) pi.dwThreadId);

    if ( ResumeThread ( pi.hThread ) < 0 ) {
        DEBUG1 ("ResumeThread failed: ec=%d\n", (int)GetLastError ());
    }

    if ( !CloseHandle (pi.hThread) ) { 
        DEBUG1 ("CloseHandle of thread failed: ec=%d\n",
                 (int)GetLastError ());
    }

    return 0;
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
  int     npollfds;
  GPollFD *pollfds;
  int     *pollfds_map; 
  int i, j;
  int any, n, count;
  int timeout = 1000;  /* Use a 1s timeout.  */
  void *dbg_help = NULL;

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

  DEBUG_BEGIN (dbg_help, 3, "gpgme:select on [ ");
  any = 0;
  for (i = 0; i < nfds; i++)
    {
      if (fds[i].fd == -1) 
	continue;
      if (fds[i].frozen)
	DEBUG_ADD1 (dbg_help, "f%d ", fds[i].fd);
      else if (fds[i].for_read )
	{
          GIOChannel *chan = find_channel (fds[i].fd, 0);
          assert (chan);
          g_io_channel_win32_make_pollfd (chan, G_IO_IN, pollfds + npollfds);
          pollfds_map[npollfds] = i;
	  DEBUG_ADD2 (dbg_help, "r%d<%d> ", fds[i].fd, pollfds[npollfds].fd);
          npollfds++;
	  any = 1;
        }
      else if (fds[i].for_write)
	{
          GIOChannel *chan = find_channel (fds[i].fd, 0);
          assert (chan);
          g_io_channel_win32_make_pollfd (chan, G_IO_OUT, pollfds + npollfds);
          pollfds_map[npollfds] = i;
	  DEBUG_ADD2 (dbg_help, "w%d<%d> ", fds[i].fd, pollfds[npollfds].fd);
          npollfds++;
	  any = 1;
        }
      fds[i].signaled = 0;
    }
  DEBUG_END (dbg_help, "]"); 
  if (!any)
    {
      count = 0;
      goto leave;
    }


  count = g_io_channel_win32_poll (pollfds, npollfds, timeout);
  if (count < 0)
    {
      int saved_errno = errno;
      DEBUG1 ("_gpgme_io_select failed: %s\n", strerror (errno));
      errno = saved_errno;
      goto leave;
    }

  DEBUG_BEGIN (dbg_help, 3, "select OK [ ");
  if (DEBUG_ENABLED (dbg_help))
    {
      for (i = 0; i < npollfds; i++)
	{
	  if ((pollfds[i].revents & G_IO_IN))
	    DEBUG_ADD1 (dbg_help, "r%d ", fds[pollfds_map[i]].fd);
          if ((pollfds[i].revents & G_IO_OUT))
            DEBUG_ADD1 (dbg_help, "w%d ", fds[pollfds_map[i]].fd);
        }
      DEBUG_END (dbg_help, "]");
    }
    
  /* COUNT is used to stop the lop as soon as possible.  */
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
  return count;
}
