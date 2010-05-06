/* w32-qt-io.c - W32 Glib I/O functions
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2004, 2005, 2007 g10 Code GmbH

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
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <windows.h>
#include <io.h>

#include "kdpipeiodevice.h"

extern "C"
{
#include "util.h"
#include "priv-io.h"
#include "sema.h"
#include "debug.h"
}

#ifndef O_BINARY
#ifdef _O_BINARY
#define O_BINARY	_O_BINARY
#else
#define O_BINARY	0
#endif
#endif

using _gpgme_::KDPipeIODevice;


/* This file is an ugly hack to get GPGME working with Qt on Windows
   targets.  On Windows, you can not select() on file descriptors.

   The only way to check if there is something to read is to read
   something.  This means that GPGME can not let Qt check for data
   without letting Qt also handle the data on Windows targets.

   The ugly consequence is that we need to work on QIODevices in
   GPGME, creating a Qt dependency.  Also, we need to export an
   interface for the application to get at GPGME's QIODevices.  There
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

#define MAX_SLAFD 1024

struct DeviceEntry {
  DeviceEntry() : iodev( 0 ), refCount( 1 ), blocking( true ) {}
    KDPipeIODevice* iodev;
    bool blocking;
    mutable int refCount;
    void ref() const { ++refCount; }
    int unref() const { assert( refCount > 0 ); return --refCount; }
};

DeviceEntry* iodevice_table[MAX_SLAFD];


static KDPipeIODevice *
find_channel (int fd, int create)
{
  assert( fd < MAX_SLAFD );
  if (fd < 0 || fd >= MAX_SLAFD)
    return NULL;

  if (create && !iodevice_table[fd])
  {
    DeviceEntry* entry = new DeviceEntry;
    entry->iodev = new KDPipeIODevice
      (fd, QIODevice::ReadWrite|QIODevice::Unbuffered);
    iodevice_table[fd] = entry; 
  }
  return iodevice_table[fd] ? iodevice_table[fd]->iodev : 0;
}

/* Write the printable version of FD to the buffer BUF of length
   BUFLEN.  The printable version is the representation on the command
   line that the child process expects.  */
int
_gpgme_io_fd2str (char *buf, int buflen, int fd)
{
  return snprintf (buf, buflen, "%d", (long)_get_osfhandle( fd ) );
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
  qint64 nread;
  KDPipeIODevice *chan;
  TRACE_BEG2 (DEBUG_SYSIO, "_gpgme_io_read", fd,
	      "buffer=%p, count=%u", buffer, count);

  chan = find_channel (fd, 0);
  if (!chan)
    {
      TRACE_LOG ("no channel registered");
      errno = EINVAL;
      return TRACE_SYSRES (-1);
    }
  TRACE_LOG1 ("channel %p", chan);
  if ( iodevice_table[fd] && !iodevice_table[fd]->blocking && chan->readWouldBlock() ) {
      errno = EAGAIN;
      return TRACE_SYSRES( -1 );
  }
 
  nread = chan->read ((char *) buffer, count);
  if (nread < 0)
    {
      TRACE_LOG1 ("err %s", qPrintable (chan->errorString ()));
      saved_errno = EIO;
      nread = -1;
    }

  TRACE_LOGBUF ((char *) buffer, nread);

  errno = saved_errno;
  return TRACE_SYSRES (nread);
}


int
_gpgme_io_write (int fd, const void *buffer, size_t count)
{
  qint64 nwritten;
  KDPipeIODevice *chan;
  TRACE_BEG2 (DEBUG_SYSIO, "_gpgme_io_write", fd,
	      "buffer=%p, count=%u", buffer, count);
  TRACE_LOGBUF ((char *) buffer, count);

  chan = find_channel (fd, 0);
  if (!chan)
    {
      TRACE_LOG ("fd %d: no channel registered");
      errno = EINVAL;
      return -1;
    }

  if ( iodevice_table[fd] && !iodevice_table[fd]->blocking && chan->writeWouldBlock() )
  {
      errno = EAGAIN;
      return TRACE_SYSRES( -1 );
  }
  nwritten = chan->write ((char *) buffer, count);

  if (nwritten < 0)
    {
      nwritten = -1;
      errno = EIO;
      return TRACE_SYSRES(-1);
    }
  errno = 0;
  return TRACE_SYSRES (nwritten);
}


int
_gpgme_io_pipe (int filedes[2], int inherit_idx)
{
  KDPipeIODevice *chan;
  TRACE_BEG2 (DEBUG_SYSIO, "_gpgme_io_pipe", filedes,
	      "inherit_idx=%i (GPGME uses it for %s)",
	      inherit_idx, inherit_idx ? "reading" : "writing");

#define PIPEBUF_SIZE  4096
  if (_pipe (filedes, PIPEBUF_SIZE, O_NOINHERIT | O_BINARY) == -1)
    return TRACE_SYSRES (-1);

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
	  return TRACE_SYSRES (-1);
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
	  return TRACE_SYSRES (-1);
	}
    }

  /* Now we have a pipe with the right end inheritable.  The other end
     should have a giochannel.  */

  chan = find_channel (filedes[1 - inherit_idx], 1);

  if (!chan)
    {
      int saved_errno = errno;
      _close (filedes[0]);
      _close (filedes[1]);
      errno = saved_errno;
      return TRACE_SYSRES (-1);
    }

  return TRACE_SUC5 ("read=0x%x/%p, write=0x%x/%p, channel=%p",
	  filedes[0], (HANDLE) _get_osfhandle (filedes[0]),
	  filedes[1], (HANDLE) _get_osfhandle (filedes[1]),
	  chan);
}

int
_gpgme_io_close (int fd)
{
  KDPipeIODevice *chan;
  TRACE_BEG (DEBUG_SYSIO, "_gpgme_io_close", fd);

  if (fd < 0 || fd >= MAX_SLAFD)
    {
      errno = EBADF;
      return TRACE_SYSRES (-1);
    }

  /* First call the notify handler.  */
  if (notify_table[fd].handler)
    {
      notify_table[fd].handler (fd, notify_table[fd].value);
      notify_table[fd].handler = NULL;
      notify_table[fd].value = NULL;
    }

  /* Then do the close.  */    
  
  DeviceEntry* const entry = iodevice_table[fd];
  if ( entry ) {
      if ( entry->unref() == 0 ) {
          entry->iodev->close();
          delete entry->iodev;
          delete entry;
          iodevice_table[fd] = 0;
      }
  } else {
      _close( fd );
  }

  

  return 0;
}


int
_gpgme_io_set_close_notify (int fd, _gpgme_close_notify_handler_t handler,
			    void *value)
{
  TRACE_BEG2 (DEBUG_SYSIO, "_gpgme_io_set_close_notify", fd,
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
  DeviceEntry* const entry = iodevice_table[fd];
  assert( entry );
  entry->blocking = false; 
  TRACE_BEG (DEBUG_SYSIO, "_gpgme_io_set_nonblocking", fd);
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

  buf = p = (char *) malloc (n);
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
      0         /* returns tid */
    };
  STARTUPINFO si;
  int cr_flags = CREATE_DEFAULT_ERROR_MODE
    | GetPriorityClass (GetCurrentProcess ());
  int i;
  char **args;
  char *arg_string;
  /* FIXME.  */
  int debug_me = 0;
  int tmp_fd;
  char *tmp_name;

  TRACE_BEG1 (DEBUG_SYSIO, "_gpgme_io_spawn", path,
	      "path=%s", path);
  i = 0;
  while (argv[i])
    {
      TRACE_LOG2 ("argv[%2i] = %s", i, argv[i]);
      i++;
    }
  
  /* We do not inherit any handles by default, and just insert those
     handles we want the child to have afterwards.  But some handle
     values occur on the command line, and we need to move
     stdin/out/err to the right location.  So we use a wrapper program
     which gets the information from a temporary file.  */
  if (_gpgme_mkstemp (&tmp_fd, &tmp_name) < 0)
    {
      TRACE_LOG1 ("_gpgme_mkstemp failed: %s", strerror (errno));
      return TRACE_SYSRES (-1);
    }
  TRACE_LOG1 ("tmp_name = %s", tmp_name);

  args = (char **) calloc (2 + i + 1, sizeof (*args));
  args[0] = (char *) _gpgme_get_w32spawn_path ();
  args[1] = tmp_name;
  args[2] = const_cast<char *>(path);
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
      TRACE_LOG1 ("CreateProcess failed: ec=%d", (int) GetLastError ());
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

      if (!DuplicateHandle (GetCurrentProcess(),
			    (HANDLE) _get_osfhandle (fd_list[i].fd),
			    pi.hProcess, &hd, 0, TRUE, DUPLICATE_SAME_ACCESS))
	{
	  TRACE_LOG1 ("DuplicateHandle failed: ec=%d", (int) GetLastError ());
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
  
  TRACE_LOG4 ("CreateProcess ready: hProcess=%p, hThread=%p, "
	      "dwProcessID=%d, dwThreadId=%d",
	      pi.hProcess, pi.hThread, 
	      (int) pi.dwProcessId, (int) pi.dwThreadId);

  if (r_pid)
    *r_pid = (pid_t)pi.dwProcessId;
  
  if (ResumeThread (pi.hThread) < 0)
    TRACE_LOG1 ("ResumeThread failed: ec=%d", (int) GetLastError ());
  
  if (!CloseHandle (pi.hThread))
    TRACE_LOG1 ("CloseHandle of thread failed: ec=%d",
		(int) GetLastError ());

  TRACE_LOG1 ("process=%p", pi.hProcess);

  /* We don't need to wait for the process.  */
  if (!CloseHandle (pi.hProcess))
    TRACE_LOG1 ("CloseHandle of process failed: ec=%d",
		(int) GetLastError ());

  for (i = 0; fd_list[i].fd != -1; i++)
    _gpgme_io_close (fd_list[i].fd);

  for (i = 0; fd_list[i].fd != -1; i++)
    if (fd_list[i].dup_to == -1)
      TRACE_LOG3 ("fd[%i] = 0x%x -> 0x%x", i, fd_list[i].fd,
		  fd_list[i].peer_name);
    else
      TRACE_LOG4 ("fd[%i] = 0x%x -> 0x%x (std%s)", i, fd_list[i].fd,
		  fd_list[i].peer_name, (fd_list[i].dup_to == 0) ? "in" :
		  ((fd_list[i].dup_to == 1) ? "out" : "err"));

  return TRACE_SYSRES (0);
}


/* Select on the list of fds.  Returns: -1 = error, 0 = timeout or
   nothing to select, > 0 = number of signaled fds.  */
int
_gpgme_io_select (struct io_select_fd_s *fds, size_t nfds, int nonblock)
{
  /* Use a 1s timeout.  */

  void *dbg_help = NULL;
  TRACE_BEG2 (DEBUG_SYSIO, "_gpgme_io_select", fds,
	      "nfds=%u, nonblock=%u", nfds, nonblock);

  int count = 0;

  TRACE_SEQ (dbg_help, "select on [ ");
  for (int i = 0; i < nfds; i++)
    {
      if (fds[i].fd == -1)
        {
          fds[i].signaled = 0;
	}
      else if (fds[i].for_read )
      {
          KDPipeIODevice * const chan = find_channel (fds[i].fd, 0);
          assert (chan);
          if ( nonblock )
              fds[i].signaled = chan->readWouldBlock() ? 0 : 1;
          else
              fds[i].signaled = chan->waitForReadyRead( 1000 ) ? 1 : 0;
	  TRACE_ADD1 (dbg_help, "w0x%x ", fds[i].fd);
          if ( fds[i].signaled ) 
              count++;
        }
      else if (fds[i].for_write)
        {
          const KDPipeIODevice * const chan = find_channel (fds[i].fd, 0);
          assert (chan);
          fds[i].signaled = nonblock ? ( chan->writeWouldBlock() ? 0 : 1 ) : 1;
          TRACE_ADD1 (dbg_help, "w0x%x ", fds[i].fd);
          if ( fds[i].signaled ) 
              count++;
        }
    }
  TRACE_END (dbg_help, "]"); 

  return TRACE_SYSRES (count);
}


/* Look up the qiodevice for file descriptor FD.  */
extern "C"
void *
gpgme_get_fdptr (int fd)
{
  return find_channel (fd, 0);
}


/* Obsolete compatibility interface.  */
extern "C"
void *
gpgme_get_giochannel (int fd)
{
  return NULL;
}


int
_gpgme_io_dup (int fd)
{
    assert( iodevice_table[fd] );
    iodevice_table[fd]->ref();
    return fd;
}


extern "C"
int
_gpgme_io_socket (int domain, int type, int proto)
{
  errno = EIO;
  return -1;
}


extern "C"
int
_gpgme_io_connect (int fd, struct sockaddr *addr, int addrlen)
{
  errno = EIO;
  return -1;
}
