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
#include <windows.h>
#include <io.h>

#include "util.h"
#include "priv-io.h"
#include "sema.h"
#include "debug.h"

#include <glib.h>


static GIOChannel *giochannel_table[256];

static HANDLE handle_table[256];
#define fd_to_handle(x) handle_table[x]

static GIOChannel *
find_channel (int fd, int create)
{
  if (fd < 0 || fd > (int) DIM (giochannel_table))
    return NULL;

  if (giochannel_table[fd] == NULL && create)
    giochannel_table[fd] = g_io_channel_unix_new (fd);

  return giochannel_table[fd];
}


/* Look up the giochannel for file descriptor FD.  */
GIOChannel *
gpgme_get_giochannel (int fd)
{
  return find_channel (fd, 0);
}


void
_gpgme_io_subsystem_init (void)
{
}


static struct
{
  void (*handler) (int,void*);
  void *value;
} notify_table[256];

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

  status = g_io_channel_read_chars (chan, (gchar *) buffer,
				    count, &nread, NULL);
  if (status == G_IO_STATUS_EOF)
    nread = 0;
  else if (status != G_IO_STATUS_NORMAL)
    {
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
_gpgme_io_pipe ( int filedes[2], int inherit_idx )
{
    HANDLE r, w;
    SECURITY_ATTRIBUTES sec_attr;

    memset (&sec_attr, 0, sizeof sec_attr );
    sec_attr.nLength = sizeof sec_attr;
    sec_attr.bInheritHandle = FALSE;
    
#define PIPEBUF_SIZE  4096
    if (!CreatePipe ( &r, &w, &sec_attr, PIPEBUF_SIZE))
        return -1;
    /* Make one end inheritable. */
    if ( inherit_idx == 0 ) {
        HANDLE h;
        if (!DuplicateHandle( GetCurrentProcess(), r,
                              GetCurrentProcess(), &h, 0,
                              TRUE, DUPLICATE_SAME_ACCESS ) ) {
            DEBUG1 ("DuplicateHandle failed: ec=%d\n", (int)GetLastError());
            CloseHandle (r);
            CloseHandle (w);
            return -1;
        }
        CloseHandle (r);
        r = h;
    }
    else if ( inherit_idx == 1 ) {
        HANDLE h;
        if (!DuplicateHandle( GetCurrentProcess(), w,
                              GetCurrentProcess(), &h, 0,
                              TRUE, DUPLICATE_SAME_ACCESS ) ) {
            DEBUG1 ("DuplicateHandle failed: ec=%d\n", (int)GetLastError());
            CloseHandle (r);
            CloseHandle (w);
            return -1;
        }
        CloseHandle (w);
        w = h;
    }
    filedes[0] = _open_osfhandle ((long) r, 0 );
    if (filedes[0] == -1)
      {
	DEBUG1 ("_open_osfhandle failed: ec=%d\n", errno);
	CloseHandle (r);
	CloseHandle (w);
	return -1;
      }
    filedes[1] = _open_osfhandle ((long) w, 0 );
      {
	DEBUG1 ("_open_osfhandle failed: ec=%d\n", errno);
	_gpgme_io_close (filedes[0]);
	CloseHandle (r);
	CloseHandle (w);
	return -1;
      }

    /* The fd that is not inherited will be used locally.  Create a
       channel for it.  */
    if (inherit_idx == 0)
      {
	if (!find_channel (filedes[1], 1))
	  {
	    DEBUG1 ("channel creation failed for %d\n", filedes[1]);
	    _gpgme_io_close (filedes[0]);
	    _gpgme_io_close (filedes[1]);
	    CloseHandle (r);
	    CloseHandle (w);
	    return -1;
	  }
      }
    else
      {
	if (!find_channel (filedes[0], 1))
	  {
	    DEBUG1 ("channel creation failed for %d\n", filedes[1]);
	    _gpgme_io_close (filedes[0]);
	    _gpgme_io_close (filedes[1]);
	    CloseHandle (r);
	    CloseHandle (w);
	    return -1;
	  }
      }

    /* Remember the handles for later.  */
    handle_table[filedes[0]] = r;
    handle_table[filedes[1]] = w;

    DEBUG5 ("CreatePipe %p %p %d %d inherit=%d\n", r, w,
                   filedes[0], filedes[1], inherit_idx );
    return 0;
}


int
_gpgme_io_close (int fd)
{
  GIOChannel *chan;

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
  chan = find_channel (fd, 0);
  if (chan)
    {
      g_io_channel_shutdown (chan, 1, NULL);
      g_io_channel_unref (chan);
      giochannel_table[fd] = NULL;
      return 0;
    }
  else
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
  GIOChannel *chan;
  GIOStatus status;

  chan = find_channel (fd, 0);
  if (!chan)
    {
      errno = EIO;
      return -1;
    }

  status = g_io_channel_set_flags (chan,
				   g_io_channel_get_flags (chan) |
				   G_IO_FLAG_NONBLOCK, NULL);
  if (status != G_IO_STATUS_NORMAL)
    {
      errno = EIO;
      return -1;
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

    memset (&sec_attr, 0, sizeof sec_attr );
    sec_attr.nLength = sizeof sec_attr;
    sec_attr.bInheritHandle = FALSE;

    arg_string = build_commandline ( argv );
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
            si.hStdInput = fd_to_handle (fd_child_list[i].fd);
            DEBUG1 ("using %d for stdin", fd_child_list[i].fd );
            duped_stdin=1;
        }
        else if (fd_child_list[i].dup_to == 1 ) {
            si.hStdOutput = fd_to_handle (fd_child_list[i].fd);
            DEBUG1 ("using %d for stdout", fd_child_list[i].fd );
        }
        else if (fd_child_list[i].dup_to == 2 ) {
            si.hStdError = fd_to_handle (fd_child_list[i].fd);
            DEBUG1 ("using %d for stderr", fd_child_list[i].fd );
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
  assert (!"ARGH!  The user of this library MUST define io callbacks!");
  errno = EINVAL;
  return -1;
}
