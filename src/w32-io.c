/* w32-io.c - W32 API I/O functions.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004, 2007, 2010 g10 Code GmbH

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
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <io.h>

#include "util.h"

#ifdef HAVE_W32CE_SYSTEM
#include <assuan.h>
#include <winioctl.h>
#define GPGCEDEV_IOCTL_UNBLOCK                                        \
  CTL_CODE (FILE_DEVICE_STREAMS, 2050, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define GPGCEDEV_IOCTL_ASSIGN_RVID                                    \
  CTL_CODE (FILE_DEVICE_STREAMS, 2051, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#include "sema.h"
#include "priv-io.h"
#include "debug.h"
#include "sys-util.h"


/* FIXME: Optimize.  */
#define MAX_SLAFD 512

static struct
{
  int used;

  /* If this is not INVALID_HANDLE_VALUE, then it's a handle.  */
  HANDLE handle;

  /* If this is not INVALID_SOCKET, then it's a Windows socket.  */
  int socket;

  /* If this is not 0, then it's a rendezvous ID for the pipe server.  */
  int rvid;

  /* DUP_FROM is -1 if this file descriptor was allocated by pipe or
     socket functions.  Only then should the handle or socket be
     destroyed when this FD is closed.  This, together with the fact
     that dup'ed file descriptors are closed before the file
     descriptors from which they are dup'ed are closed, ensures that
     the handle or socket is always valid, and shared among all file
     descriptors referring to the same underlying object.

     The logic behind this is that there is only one reason for us to
     dup file descriptors anyway: to allow simpler book-keeping of
     file descriptors shared between GPGME and libassuan, which both
     want to close something.  Using the same handle for these
     duplicates works just fine.  */
  int dup_from;
} fd_table[MAX_SLAFD];


/* Returns the FD or -1 on resource limit.  */
int
new_fd (void)
{
  int idx;

  for (idx = 0; idx < MAX_SLAFD; idx++)
    if (! fd_table[idx].used)
      break;

  if (idx == MAX_SLAFD)
    {
      gpg_err_set_errno (EIO);
      return -1;
    }

  fd_table[idx].used = 1;
  fd_table[idx].handle = INVALID_HANDLE_VALUE;
  fd_table[idx].socket = INVALID_SOCKET;
  fd_table[idx].rvid = 0;
  fd_table[idx].dup_from = -1;

  return idx;
}


void
release_fd (int fd)
{
  if (fd < 0 || fd >= MAX_SLAFD || !fd_table[fd].used)
    return;

  fd_table[fd].used = 0;
  fd_table[fd].handle = INVALID_HANDLE_VALUE;
  fd_table[fd].socket = INVALID_SOCKET;
  fd_table[fd].rvid = 0;
  fd_table[fd].dup_from = -1;
}


#define handle_to_fd(a)  ((int)(a))

#define READBUF_SIZE 4096
#define WRITEBUF_SIZE 4096
#define PIPEBUF_SIZE  4096
#define MAX_READERS 64
#define MAX_WRITERS 64

static struct
{
  int inuse;
  int fd;
  _gpgme_close_notify_handler_t handler;
  void *value;
} notify_table[MAX_SLAFD];
DEFINE_STATIC_LOCK (notify_table_lock);


struct reader_context_s
{
  HANDLE file_hd;
  int file_sock;
  HANDLE thread_hd;
  int refcount;

  DECLARE_LOCK (mutex);

  int stop_me;
  int eof;
  int eof_shortcut;
  int error;
  int error_code;

  /* This is manually reset.  */
  HANDLE have_data_ev;
  /* This is automatically reset.  */
  HANDLE have_space_ev;
  /* This is manually reset but actually only triggered once.  */
  HANDLE close_ev;

  size_t readpos, writepos;
  char buffer[READBUF_SIZE];
};


static struct
{
  volatile int used;
  int fd;
  struct reader_context_s *context;
} reader_table[MAX_READERS];
static int reader_table_size= MAX_READERS;
DEFINE_STATIC_LOCK (reader_table_lock);


struct writer_context_s
{
  HANDLE file_hd;
  int file_sock;
  HANDLE thread_hd;
  int refcount;

  DECLARE_LOCK (mutex);

  int stop_me;
  int error;
  int error_code;

  /* This is manually reset.  */
  HANDLE have_data;
  HANDLE is_empty;
  HANDLE close_ev;
  size_t nbytes;
  char buffer[WRITEBUF_SIZE];
};


static struct
{
  volatile int used;
  int fd;
  struct writer_context_s *context;
} writer_table[MAX_WRITERS];
static int writer_table_size= MAX_WRITERS;
DEFINE_STATIC_LOCK (writer_table_lock);


static int
get_desired_thread_priority (void)
{
  int value;

  if (!_gpgme_get_conf_int ("IOThreadPriority", &value))
    {
      value = THREAD_PRIORITY_HIGHEST;
      TRACE1 (DEBUG_SYSIO, "gpgme:get_desired_thread_priority", 0,
	      "%d (default)", value);
    }
  else
    {
      TRACE1 (DEBUG_SYSIO, "gpgme:get_desired_thread_priority", 0,
	      "%d (configured)", value);
    }
  return value;
}


static HANDLE
set_synchronize (HANDLE hd)
{
#ifdef HAVE_W32CE_SYSTEM
  return hd;
#else
  HANDLE new_hd;

  /* For NT we have to set the sync flag.  It seems that the only way
     to do it is by duplicating the handle.  Tsss...  */
  if (!DuplicateHandle (GetCurrentProcess (), hd,
			GetCurrentProcess (), &new_hd,
			EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, 0))
    {
      TRACE1 (DEBUG_SYSIO, "gpgme:set_synchronize", hd,
	      "DuplicateHandle failed: ec=%d", (int) GetLastError ());
      /* FIXME: Should translate the error code.  */
      gpg_err_set_errno (EIO);
      return INVALID_HANDLE_VALUE;
    }

  CloseHandle (hd);
  return new_hd;
#endif
}


static DWORD CALLBACK
reader (void *arg)
{
  struct reader_context_s *ctx = arg;
  int nbytes;
  DWORD nread;
  int sock;
  TRACE_BEG2 (DEBUG_SYSIO, "gpgme:reader", ctx->file_hd,
	      "file_sock=%d, thread=%p", ctx->file_sock, ctx->thread_hd);

  if (ctx->file_hd != INVALID_HANDLE_VALUE)
    sock = 0;
  else
    sock = 1;

  for (;;)
    {
      LOCK (ctx->mutex);
      /* Leave a 1 byte gap so that we can see whether it is empty or
	 full.  */
      if ((ctx->writepos + 1) % READBUF_SIZE == ctx->readpos)
	{
	  /* Wait for space.  */
	  if (!ResetEvent (ctx->have_space_ev))
	    TRACE_LOG1 ("ResetEvent failed: ec=%d", (int) GetLastError ());
	  UNLOCK (ctx->mutex);
	  TRACE_LOG ("waiting for space");
	  WaitForSingleObject (ctx->have_space_ev, INFINITE);
	  TRACE_LOG ("got space");
	  LOCK (ctx->mutex);
       	}
      if (ctx->stop_me)
	{
	  UNLOCK (ctx->mutex);
	  break;
        }
      nbytes = (ctx->readpos + READBUF_SIZE
		- ctx->writepos - 1) % READBUF_SIZE;
      if (nbytes > READBUF_SIZE - ctx->writepos)
	nbytes = READBUF_SIZE - ctx->writepos;
      UNLOCK (ctx->mutex);

      TRACE_LOG2 ("%s %d bytes", sock? "receiving":"reading", nbytes);

      if (sock)
        {
          int n;

          n = recv (ctx->file_sock, ctx->buffer + ctx->writepos, nbytes, 0);
          if (n < 0)
            {
              ctx->error_code = (int) WSAGetLastError ();
              if (ctx->error_code == ERROR_BROKEN_PIPE)
                {
                  ctx->eof = 1;
                  TRACE_LOG ("got EOF (broken connection)");
                }
              else
                {
                  /* Check whether the shutdown triggered the error -
                     no need to to print a warning in this case.  */
                  if ( ctx->error_code == WSAECONNABORTED
                       || ctx->error_code == WSAECONNRESET)
                    {
                      LOCK (ctx->mutex);
                      if (ctx->stop_me)
                        {
                          UNLOCK (ctx->mutex);
                          TRACE_LOG ("got shutdown");
                          break;
                        }
                      UNLOCK (ctx->mutex);
                    }

                  ctx->error = 1;
                  TRACE_LOG1 ("recv error: ec=%d", ctx->error_code);
                }
              break;
            }
          nread = n;
        }
      else
        {
          if (!ReadFile (ctx->file_hd,
                         ctx->buffer + ctx->writepos, nbytes, &nread, NULL))
            {
              ctx->error_code = (int) GetLastError ();
	      /* NOTE (W32CE): Do not ignore ERROR_BUSY!  Check at
		 least stop_me if that happens.  */
              if (ctx->error_code == ERROR_BROKEN_PIPE)
                {
                  ctx->eof = 1;
                  TRACE_LOG ("got EOF (broken pipe)");
                }
              else
                {
                  ctx->error = 1;
                  TRACE_LOG1 ("read error: ec=%d", ctx->error_code);
                }
              break;
            }
        }
      LOCK (ctx->mutex);
      if (ctx->stop_me)
	{
	  UNLOCK (ctx->mutex);
	  break;
        }
      if (!nread)
	{
	  ctx->eof = 1;
	  TRACE_LOG ("got eof");
	  UNLOCK (ctx->mutex);
	  break;
        }

      TRACE_LOG1 ("got %u bytes", nread);

      ctx->writepos = (ctx->writepos + nread) % READBUF_SIZE;
      if (!SetEvent (ctx->have_data_ev))
	TRACE_LOG2 ("SetEvent (0x%x) failed: ec=%d", ctx->have_data_ev,
		    (int) GetLastError ());
      UNLOCK (ctx->mutex);
    }
  /* Indicate that we have an error or EOF.  */
  if (!SetEvent (ctx->have_data_ev))
    TRACE_LOG2 ("SetEvent (0x%x) failed: ec=%d", ctx->have_data_ev,
                (int) GetLastError ());

  TRACE_LOG ("waiting for close");
  WaitForSingleObject (ctx->close_ev, INFINITE);

  CloseHandle (ctx->close_ev);
  CloseHandle (ctx->have_data_ev);
  CloseHandle (ctx->have_space_ev);
  CloseHandle (ctx->thread_hd);
  DESTROY_LOCK (ctx->mutex);
  free (ctx);

  return TRACE_SUC ();
}


static struct reader_context_s *
create_reader (int fd)
{
  struct reader_context_s *ctx;
  SECURITY_ATTRIBUTES sec_attr;
  DWORD tid;

  TRACE_BEG (DEBUG_SYSIO, "gpgme:create_reader", fd);

  memset (&sec_attr, 0, sizeof sec_attr);
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = FALSE;

  ctx = calloc (1, sizeof *ctx);
  if (!ctx)
    {
      TRACE_SYSERR (errno);
      return NULL;
    }

  if (fd < 0 || fd >= MAX_SLAFD || !fd_table[fd].used)
    {
      TRACE_SYSERR (EIO);
      free (ctx);
      return NULL;
    }
  TRACE_LOG4 ("fd=%d -> handle=%p socket=%d dupfrom=%d",
              fd, fd_table[fd].handle, fd_table[fd].socket,
              fd_table[fd].dup_from);
  ctx->file_hd = fd_table[fd].handle;
  ctx->file_sock = fd_table[fd].socket;

  ctx->refcount = 1;
  ctx->have_data_ev = CreateEvent (&sec_attr, TRUE, FALSE, NULL);
  if (ctx->have_data_ev)
    ctx->have_space_ev = CreateEvent (&sec_attr, FALSE, TRUE, NULL);
  if (ctx->have_space_ev)
    ctx->close_ev = CreateEvent (&sec_attr, TRUE, FALSE, NULL);
  if (!ctx->have_data_ev || !ctx->have_space_ev || !ctx->close_ev)
    {
      TRACE_LOG1 ("CreateEvent failed: ec=%d", (int) GetLastError ());
      if (ctx->have_data_ev)
	CloseHandle (ctx->have_data_ev);
      if (ctx->have_space_ev)
	CloseHandle (ctx->have_space_ev);
      if (ctx->close_ev)
	CloseHandle (ctx->close_ev);
      free (ctx);
      /* FIXME: Translate the error code.  */
      TRACE_SYSERR (EIO);
      return NULL;
    }

  ctx->have_data_ev = set_synchronize (ctx->have_data_ev);
  INIT_LOCK (ctx->mutex);

#ifdef HAVE_W32CE_SYSTEM
  ctx->thread_hd = CreateThread (&sec_attr, 64 * 1024, reader, ctx,
				 STACK_SIZE_PARAM_IS_A_RESERVATION, &tid);
#else
  ctx->thread_hd = CreateThread (&sec_attr, 0, reader, ctx, 0, &tid);
#endif

  if (!ctx->thread_hd)
    {
      TRACE_LOG1 ("CreateThread failed: ec=%d", (int) GetLastError ());
      DESTROY_LOCK (ctx->mutex);
      if (ctx->have_data_ev)
	CloseHandle (ctx->have_data_ev);
      if (ctx->have_space_ev)
	CloseHandle (ctx->have_space_ev);
      if (ctx->close_ev)
	CloseHandle (ctx->close_ev);
      free (ctx);
      TRACE_SYSERR (EIO);
      return NULL;
    }
  else
    {
      /* We set the priority of the thread higher because we know that
         it only runs for a short time.  This greatly helps to
         increase the performance of the I/O.  */
      SetThreadPriority (ctx->thread_hd, get_desired_thread_priority ());
    }

  TRACE_SUC ();
  return ctx;
}


/* Prepare destruction of the reader thread for CTX.  Returns 0 if a
   call to this function is sufficient and destroy_reader_finish shall
   not be called.  */
static void
destroy_reader (struct reader_context_s *ctx)
{
  LOCK (ctx->mutex);
  ctx->refcount--;
  if (ctx->refcount != 0)
    {
      UNLOCK (ctx->mutex);
      return;
    }
  ctx->stop_me = 1;
  if (ctx->have_space_ev)
    SetEvent (ctx->have_space_ev);
  UNLOCK (ctx->mutex);

#ifdef HAVE_W32CE_SYSTEM
  /* Scenario: We never create a full pipe, but already started
     reading.  Then we need to unblock the reader in the pipe driver
     to make our reader thread notice that we want it to go away.  */

  if (ctx->file_hd != INVALID_HANDLE_VALUE)
    {
      if (!DeviceIoControl (ctx->file_hd, GPGCEDEV_IOCTL_UNBLOCK,
			NULL, 0, NULL, 0, NULL, NULL))
	{
	  TRACE1 (DEBUG_SYSIO, "gpgme:destroy_reader", ctx->file_hd,
		  "unblock control call failed for thread %p", ctx->thread_hd);
	}
    }
#endif

  /* The reader thread is usually blocking in recv or ReadFile.  If
     the peer does not send an EOF or breaks the pipe the WFSO might
     get stuck waiting for the termination of the reader thread.  This
     happens quite often with sockets, thus we definitely need to get
     out of the recv.  A shutdown does this nicely.  For handles
     (i.e. pipes) it would also be nice to cancel the operation, but
     such a feature is only available since Vista.  Thus we need to
     dlopen that syscall.  */
  if (ctx->file_hd != INVALID_HANDLE_VALUE)
    {
      /* Fixme: Call CancelSynchronousIo (handle_of_thread).  */
    }
  else if (ctx->file_sock != INVALID_SOCKET)
    {
      if (shutdown (ctx->file_sock, 2))
        TRACE2 (DEBUG_SYSIO, "gpgme:destroy_reader", ctx->file_hd,
                "shutdown socket %d failed: %s",
                ctx->file_sock, (int) WSAGetLastError ());
    }

  /* After setting this event CTX is void. */
  SetEvent (ctx->close_ev);
}



/* Find a reader context or create a new one.  Note that the reader
   context will last until a _gpgme_io_close.  */
static struct reader_context_s *
find_reader (int fd, int start_it)
{
  struct reader_context_s *rd = NULL;
  int i;

  LOCK (reader_table_lock);
  for (i = 0; i < reader_table_size; i++)
    if (reader_table[i].used && reader_table[i].fd == fd)
      rd = reader_table[i].context;

  if (rd || !start_it)
    {
      UNLOCK (reader_table_lock);
      return rd;
    }

  for (i = 0; i < reader_table_size; i++)
    if (!reader_table[i].used)
      break;

  if (i != reader_table_size)
    {
      rd = create_reader (fd);
      reader_table[i].fd = fd;
      reader_table[i].context = rd;
      reader_table[i].used = 1;
    }

  UNLOCK (reader_table_lock);
  return rd;
}


int
_gpgme_io_read (int fd, void *buffer, size_t count)
{
  int nread;
  struct reader_context_s *ctx;
  TRACE_BEG2 (DEBUG_SYSIO, "_gpgme_io_read", fd,
	      "buffer=%p, count=%u", buffer, count);

  ctx = find_reader (fd, 1);
  if (!ctx)
    {
      gpg_err_set_errno (EBADF);
      return TRACE_SYSRES (-1);
    }
  if (ctx->eof_shortcut)
    return TRACE_SYSRES (0);

  LOCK (ctx->mutex);
  if (ctx->readpos == ctx->writepos && !ctx->error)
    {
      /* No data available.  */
      UNLOCK (ctx->mutex);
      TRACE_LOG1 ("waiting for data from thread %p", ctx->thread_hd);
      WaitForSingleObject (ctx->have_data_ev, INFINITE);
      TRACE_LOG1 ("data from thread %p available", ctx->thread_hd);
      LOCK (ctx->mutex);
    }

  if (ctx->readpos == ctx->writepos || ctx->error)
    {
      UNLOCK (ctx->mutex);
      ctx->eof_shortcut = 1;
      if (ctx->eof)
	return TRACE_SYSRES (0);
      if (!ctx->error)
	{
	  TRACE_LOG ("EOF but ctx->eof flag not set");
	  return 0;
	}
      gpg_err_set_errno (ctx->error_code);
      return TRACE_SYSRES (-1);
    }

  nread = ctx->readpos < ctx->writepos
    ? ctx->writepos - ctx->readpos
    : READBUF_SIZE - ctx->readpos;
  if (nread > count)
    nread = count;
  memcpy (buffer, ctx->buffer + ctx->readpos, nread);
  ctx->readpos = (ctx->readpos + nread) % READBUF_SIZE;
  if (ctx->readpos == ctx->writepos && !ctx->eof)
    {
      if (!ResetEvent (ctx->have_data_ev))
	{
	  TRACE_LOG1 ("ResetEvent failed: ec=%d", (int) GetLastError ());
	  UNLOCK (ctx->mutex);
	  /* FIXME: Should translate the error code.  */
	  gpg_err_set_errno (EIO);
	  return TRACE_SYSRES (-1);
	}
    }
  if (!SetEvent (ctx->have_space_ev))
    {
      TRACE_LOG2 ("SetEvent (0x%x) failed: ec=%d",
		  ctx->have_space_ev, (int) GetLastError ());
      UNLOCK (ctx->mutex);
      /* FIXME: Should translate the error code.  */
      gpg_err_set_errno (EIO);
      return TRACE_SYSRES (-1);
    }
  UNLOCK (ctx->mutex);

  TRACE_LOGBUF (buffer, nread);
  return TRACE_SYSRES (nread);
}


/* The writer does use a simple buffering strategy so that we are
   informed about write errors as soon as possible (i. e. with the the
   next call to the write function.  */
static DWORD CALLBACK
writer (void *arg)
{
  struct writer_context_s *ctx = arg;
  DWORD nwritten;
  int sock;
  TRACE_BEG2 (DEBUG_SYSIO, "gpgme:writer", ctx->file_hd,
	      "file_sock=%d, thread=%p", ctx->file_sock, ctx->thread_hd);

  if (ctx->file_hd != INVALID_HANDLE_VALUE)
    sock = 0;
  else
    sock = 1;

  for (;;)
    {
      LOCK (ctx->mutex);
      if (ctx->stop_me)
	{
	  UNLOCK (ctx->mutex);
	  break;
        }
      if (!ctx->nbytes)
	{
	  if (!SetEvent (ctx->is_empty))
	    TRACE_LOG1 ("SetEvent failed: ec=%d", (int) GetLastError ());
	  if (!ResetEvent (ctx->have_data))
	    TRACE_LOG1 ("ResetEvent failed: ec=%d", (int) GetLastError ());
	  UNLOCK (ctx->mutex);
	  TRACE_LOG ("idle");
	  WaitForSingleObject (ctx->have_data, INFINITE);
	  TRACE_LOG ("got data to send");
	  LOCK (ctx->mutex);
       	}
      if (ctx->stop_me)
	{
	  UNLOCK (ctx->mutex);
	  break;
        }
      UNLOCK (ctx->mutex);

      TRACE_LOG2 ("%s %d bytes", sock?"sending":"writing", ctx->nbytes);

      /* Note that CTX->nbytes is not zero at this point, because
	 _gpgme_io_write always writes at least 1 byte before waking
	 us up, unless CTX->stop_me is true, which we catch above.  */
      if (sock)
        {
          /* We need to try send first because a socket handle can't
             be used with WriteFile.  */
          int n;

          n = send (ctx->file_sock, ctx->buffer, ctx->nbytes, 0);
          if (n < 0)
            {
              ctx->error_code = (int) WSAGetLastError ();
              ctx->error = 1;
              TRACE_LOG1 ("send error: ec=%d", ctx->error_code);
              break;
            }
          nwritten = n;
        }
      else
        {
          if (!WriteFile (ctx->file_hd, ctx->buffer,
                          ctx->nbytes, &nwritten, NULL))
            {
	      if (GetLastError () == ERROR_BUSY)
		{
		  /* Probably stop_me is set now.  */
                  TRACE_LOG ("pipe busy (unblocked?)");
		  continue;
                }

              ctx->error_code = (int) GetLastError ();
              ctx->error = 1;
              TRACE_LOG1 ("write error: ec=%d", ctx->error_code);
              break;
            }
        }
      TRACE_LOG1 ("wrote %d bytes", (int) nwritten);

      LOCK (ctx->mutex);
      ctx->nbytes -= nwritten;
      UNLOCK (ctx->mutex);
    }
  /* Indicate that we have an error.  */
  if (!SetEvent (ctx->is_empty))
    TRACE_LOG1 ("SetEvent failed: ec=%d", (int) GetLastError ());

  TRACE_LOG ("waiting for close");
  WaitForSingleObject (ctx->close_ev, INFINITE);

  CloseHandle (ctx->close_ev);
  CloseHandle (ctx->have_data);
  CloseHandle (ctx->is_empty);
  CloseHandle (ctx->thread_hd);
  DESTROY_LOCK (ctx->mutex);
  free (ctx);

  return TRACE_SUC ();
}


static struct writer_context_s *
create_writer (int fd)
{
  struct writer_context_s *ctx;
  SECURITY_ATTRIBUTES sec_attr;
  DWORD tid;

  TRACE_BEG (DEBUG_SYSIO, "gpgme:create_writer", fd);

  memset (&sec_attr, 0, sizeof sec_attr);
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = FALSE;

  ctx = calloc (1, sizeof *ctx);
  if (!ctx)
    {
      TRACE_SYSERR (errno);
      return NULL;
    }

  if (fd < 0 || fd >= MAX_SLAFD || !fd_table[fd].used)
    {
      TRACE_SYSERR (EIO);
      free (ctx);
      return NULL;
    }
  TRACE_LOG4 ("fd=%d -> handle=%p socket=%d dupfrom=%d",
              fd, fd_table[fd].handle, fd_table[fd].socket,
              fd_table[fd].dup_from);
  ctx->file_hd = fd_table[fd].handle;
  ctx->file_sock = fd_table[fd].socket;

  ctx->refcount = 1;
  ctx->have_data = CreateEvent (&sec_attr, TRUE, FALSE, NULL);
  if (ctx->have_data)
    ctx->is_empty  = CreateEvent (&sec_attr, TRUE, TRUE, NULL);
  if (ctx->is_empty)
    ctx->close_ev = CreateEvent (&sec_attr, TRUE, FALSE, NULL);
  if (!ctx->have_data || !ctx->is_empty || !ctx->close_ev)
    {
      TRACE_LOG1 ("CreateEvent failed: ec=%d", (int) GetLastError ());
      if (ctx->have_data)
	CloseHandle (ctx->have_data);
      if (ctx->is_empty)
	CloseHandle (ctx->is_empty);
      if (ctx->close_ev)
	CloseHandle (ctx->close_ev);
      free (ctx);
      /* FIXME: Translate the error code.  */
      TRACE_SYSERR (EIO);
      return NULL;
    }

  ctx->is_empty = set_synchronize (ctx->is_empty);
  INIT_LOCK (ctx->mutex);

#ifdef HAVE_W32CE_SYSTEM
  ctx->thread_hd = CreateThread (&sec_attr, 64 * 1024, writer, ctx,
				 STACK_SIZE_PARAM_IS_A_RESERVATION, &tid);
#else
  ctx->thread_hd = CreateThread (&sec_attr, 0, writer, ctx, 0, &tid );
#endif

  if (!ctx->thread_hd)
    {
      TRACE_LOG1 ("CreateThread failed: ec=%d", (int) GetLastError ());
      DESTROY_LOCK (ctx->mutex);
      if (ctx->have_data)
	CloseHandle (ctx->have_data);
      if (ctx->is_empty)
	CloseHandle (ctx->is_empty);
      if (ctx->close_ev)
	CloseHandle (ctx->close_ev);
      free (ctx);
      TRACE_SYSERR (EIO);
      return NULL;
    }
  else
    {
      /* We set the priority of the thread higher because we know
	 that it only runs for a short time.  This greatly helps to
	 increase the performance of the I/O.  */
      SetThreadPriority (ctx->thread_hd, get_desired_thread_priority ());
    }

  TRACE_SUC ();
  return ctx;
}


static void
destroy_writer (struct writer_context_s *ctx)
{
  LOCK (ctx->mutex);
  ctx->refcount--;
  if (ctx->refcount != 0)
    {
      UNLOCK (ctx->mutex);
      return;
    }
  ctx->stop_me = 1;
  if (ctx->have_data)
    SetEvent (ctx->have_data);
  UNLOCK (ctx->mutex);

#ifdef HAVE_W32CE_SYSTEM
  /* Scenario: We never create a full pipe, but already started
     writing more than the pipe buffer.  Then we need to unblock the
     writer in the pipe driver to make our writer thread notice that
     we want it to go away.  */

  if (!DeviceIoControl (ctx->file_hd, GPGCEDEV_IOCTL_UNBLOCK,
			NULL, 0, NULL, 0, NULL, NULL))
    {
      TRACE1 (DEBUG_SYSIO, "gpgme:destroy_writer", ctx->file_hd,
	      "unblock control call failed for thread %p", ctx->thread_hd);
    }
#endif

  /* After setting this event CTX is void.  */
  SetEvent (ctx->close_ev);
}


/* Find a writer context or create a new one.  Note that the writer
   context will last until a _gpgme_io_close.  */
static struct writer_context_s *
find_writer (int fd, int start_it)
{
  struct writer_context_s *wt = NULL;
  int i;

  LOCK (writer_table_lock);
  for (i = 0; i < writer_table_size; i++)
    if (writer_table[i].used && writer_table[i].fd == fd)
      wt = writer_table[i].context;

  if (wt || !start_it)
    {
      UNLOCK (writer_table_lock);
      return wt;
    }

  for (i = 0; i < writer_table_size; i++)
    if (!writer_table[i].used)
      break;

  if (i != writer_table_size)
    {
      wt = create_writer (fd);
      writer_table[i].fd = fd;
      writer_table[i].context = wt;
      writer_table[i].used = 1;
    }

  UNLOCK (writer_table_lock);
  return wt;
}


int
_gpgme_io_write (int fd, const void *buffer, size_t count)
{
  struct writer_context_s *ctx;
  TRACE_BEG2 (DEBUG_SYSIO, "_gpgme_io_write", fd,
	      "buffer=%p, count=%u", buffer, count);
  TRACE_LOGBUF (buffer, count);

  if (count == 0)
    return TRACE_SYSRES (0);

  ctx = find_writer (fd, 1);
  if (!ctx)
    return TRACE_SYSRES (-1);

  LOCK (ctx->mutex);
  if (!ctx->error && ctx->nbytes)
    {
      /* Bytes are pending for send.  */

      /* Reset the is_empty event.  Better safe than sorry.  */
      if (!ResetEvent (ctx->is_empty))
	{
	  TRACE_LOG1 ("ResetEvent failed: ec=%d", (int) GetLastError ());
	  UNLOCK (ctx->mutex);
	  /* FIXME: Should translate the error code.  */
	  gpg_err_set_errno (EIO);
	  return TRACE_SYSRES (-1);
	}
      UNLOCK (ctx->mutex);
      TRACE_LOG1 ("waiting for empty buffer in thread %p", ctx->thread_hd);
      WaitForSingleObject (ctx->is_empty, INFINITE);
      TRACE_LOG1 ("thread %p buffer is empty", ctx->thread_hd);
      LOCK (ctx->mutex);
    }

  if (ctx->error)
    {
      UNLOCK (ctx->mutex);
      if (ctx->error_code == ERROR_NO_DATA)
        gpg_err_set_errno (EPIPE);
      else
        gpg_err_set_errno (EIO);
      return TRACE_SYSRES (-1);
    }

  /* If no error occurred, the number of bytes in the buffer must be
     zero.  */
  assert (!ctx->nbytes);

  if (count > WRITEBUF_SIZE)
    count = WRITEBUF_SIZE;
  memcpy (ctx->buffer, buffer, count);
  ctx->nbytes = count;

  /* We have to reset the is_empty event early, because it is also
     used by the select() implementation to probe the channel.  */
  if (!ResetEvent (ctx->is_empty))
    {
      TRACE_LOG1 ("ResetEvent failed: ec=%d", (int) GetLastError ());
      UNLOCK (ctx->mutex);
      /* FIXME: Should translate the error code.  */
      gpg_err_set_errno (EIO);
      return TRACE_SYSRES (-1);
    }
  if (!SetEvent (ctx->have_data))
    {
      TRACE_LOG1 ("SetEvent failed: ec=%d", (int) GetLastError ());
      UNLOCK (ctx->mutex);
      /* FIXME: Should translate the error code.  */
      gpg_err_set_errno (EIO);
      return TRACE_SYSRES (-1);
    }
  UNLOCK (ctx->mutex);

  return TRACE_SYSRES ((int) count);
}


int
_gpgme_io_pipe (int filedes[2], int inherit_idx)
{
  int rfd;
  int wfd;
#ifdef HAVE_W32CE_SYSTEM
  HANDLE hd;
  int rvid;
#else
  HANDLE rh;
  HANDLE wh;
  SECURITY_ATTRIBUTES sec_attr;
#endif

  TRACE_BEG2 (DEBUG_SYSIO, "_gpgme_io_pipe", filedes,
	      "inherit_idx=%i (GPGME uses it for %s)",
	      inherit_idx, inherit_idx ? "reading" : "writing");

  rfd = new_fd ();
  if (rfd == -1)
    return TRACE_SYSRES (-1);
  wfd = new_fd ();
  if (wfd == -1)
    {
      release_fd (rfd);
      return TRACE_SYSRES (-1);
    }

#ifdef HAVE_W32CE_SYSTEM
  hd = _assuan_w32ce_prepare_pipe (&rvid, !inherit_idx);
  if (hd == INVALID_HANDLE_VALUE)
    {
      TRACE_LOG1 ("_assuan_w32ce_prepare_pipe failed: ec=%d",
		  (int) GetLastError ());
      release_fd (rfd);
      release_fd (wfd);
      /* FIXME: Should translate the error code.  */
      gpg_err_set_errno (EIO);
      return TRACE_SYSRES (-1);
    }

  if (inherit_idx == 0)
    {
      fd_table[rfd].rvid = rvid;
      fd_table[wfd].handle = hd;
    }
  else
    {
      fd_table[rfd].handle = hd;
      fd_table[wfd].rvid = rvid;
    }

#else

  memset (&sec_attr, 0, sizeof (sec_attr));
  sec_attr.nLength = sizeof (sec_attr);
  sec_attr.bInheritHandle = FALSE;

  if (!CreatePipe (&rh, &wh, &sec_attr, PIPEBUF_SIZE))
    {
      TRACE_LOG1 ("CreatePipe failed: ec=%d", (int) GetLastError ());
      release_fd (rfd);
      release_fd (wfd);
      /* FIXME: Should translate the error code.  */
      gpg_err_set_errno (EIO);
      return TRACE_SYSRES (-1);
    }

  /* Make one end inheritable.  */
  if (inherit_idx == 0)
    {
      HANDLE hd;
      if (!DuplicateHandle (GetCurrentProcess(), rh,
			    GetCurrentProcess(), &hd, 0,
			    TRUE, DUPLICATE_SAME_ACCESS))
	{
	  TRACE_LOG1 ("DuplicateHandle failed: ec=%d",
		      (int) GetLastError ());
	  release_fd (rfd);
	  release_fd (wfd);
	  CloseHandle (rh);
	  CloseHandle (wh);
	  /* FIXME: Should translate the error code.  */
	  gpg_err_set_errno (EIO);
	  return TRACE_SYSRES (-1);
        }
      CloseHandle (rh);
      rh = hd;
    }
  else if (inherit_idx == 1)
    {
      HANDLE hd;
      if (!DuplicateHandle( GetCurrentProcess(), wh,
			    GetCurrentProcess(), &hd, 0,
			    TRUE, DUPLICATE_SAME_ACCESS))
	{
	  TRACE_LOG1 ("DuplicateHandle failed: ec=%d",
		      (int) GetLastError ());
	  release_fd (rfd);
	  release_fd (wfd);
	  CloseHandle (rh);
	  CloseHandle (wh);
	  /* FIXME: Should translate the error code.  */
	  gpg_err_set_errno (EIO);
	  return TRACE_SYSRES (-1);
        }
      CloseHandle (wh);
      wh = hd;
    }
  fd_table[rfd].handle = rh;
  fd_table[wfd].handle = wh;
#endif

  filedes[0] = rfd;
  filedes[1] = wfd;
  return TRACE_SUC6 ("read=0x%x (%p/0x%x), write=0x%x (%p/0x%x)",
		     rfd, fd_table[rfd].handle, fd_table[rfd].rvid,
		     wfd, fd_table[wfd].handle, fd_table[wfd].rvid);
}


int
_gpgme_io_close (int fd)
{
  int i;
  _gpgme_close_notify_handler_t handler = NULL;
  void *value = NULL;

  TRACE_BEG (DEBUG_SYSIO, "_gpgme_io_close", fd);

  if (fd == -1)
    {
      gpg_err_set_errno (EBADF);
      return TRACE_SYSRES (-1);
    }
  if (fd < 0 || fd >= MAX_SLAFD || !fd_table[fd].used)
    {
      gpg_err_set_errno (EBADF);
      return TRACE_SYSRES (-1);
    }

  TRACE_LOG4 ("fd=%d -> handle=%p socket=%d dupfrom=%d",
              fd, fd_table[fd].handle, fd_table[fd].socket,
              fd_table[fd].dup_from);

  LOCK (reader_table_lock);
  for (i = 0; i < reader_table_size; i++)
    {
      if (reader_table[i].used && reader_table[i].fd == fd)
	{
	  destroy_reader (reader_table[i].context);
	  reader_table[i].context = NULL;
	  reader_table[i].used = 0;
	  break;
	}
    }
  UNLOCK (reader_table_lock);

  LOCK (writer_table_lock);
  for (i = 0; i < writer_table_size; i++)
    {
      if (writer_table[i].used && writer_table[i].fd == fd)
	{
	  destroy_writer (writer_table[i].context);
	  writer_table[i].context = NULL;
	  writer_table[i].used = 0;
	  break;
	}
    }
  UNLOCK (writer_table_lock);

  LOCK (notify_table_lock);
  for (i = 0; i < DIM (notify_table); i++)
    {
      if (notify_table[i].inuse && notify_table[i].fd == fd)
	{
	  handler = notify_table[i].handler;
	  value   = notify_table[i].value;
	  notify_table[i].handler = NULL;
	  notify_table[i].value = NULL;
	  notify_table[i].inuse = 0;
	  break;
	}
    }
  UNLOCK (notify_table_lock);
  if (handler)
    handler (fd, value);

  if (fd_table[fd].dup_from == -1)
    {
      if (fd_table[fd].handle != INVALID_HANDLE_VALUE)
	{
	  if (!CloseHandle (fd_table[fd].handle))
	    {
	      TRACE_LOG1 ("CloseHandle failed: ec=%d", (int) GetLastError ());
	      /* FIXME: Should translate the error code.  */
	      gpg_err_set_errno (EIO);
	      return TRACE_SYSRES (-1);
	    }
	}
      else if (fd_table[fd].socket != INVALID_SOCKET)
	{
	  if (closesocket (fd_table[fd].socket))
	    {
	      TRACE_LOG1 ("closesocket failed: ec=%d", (int) WSAGetLastError ());
	      /* FIXME: Should translate the error code.  */
	      gpg_err_set_errno (EIO);
	      return TRACE_SYSRES (-1);
	    }
	}
      /* Nothing to do for RVIDs.  */
    }

  release_fd (fd);

  return TRACE_SYSRES (0);
}


int
_gpgme_io_set_close_notify (int fd, _gpgme_close_notify_handler_t handler,
			    void *value)
{
  int i;
  TRACE_BEG2 (DEBUG_SYSIO, "_gpgme_io_set_close_notify", fd,
	      "close_handler=%p/%p", handler, value);

  assert (fd != -1);

  LOCK (notify_table_lock);
  for (i=0; i < DIM (notify_table); i++)
    if (notify_table[i].inuse && notify_table[i].fd == fd)
      break;
  if (i == DIM (notify_table))
    for (i = 0; i < DIM (notify_table); i++)
      if (!notify_table[i].inuse)
	break;
  if (i == DIM (notify_table))
    {
      UNLOCK (notify_table_lock);
      gpg_err_set_errno (EINVAL);
      return TRACE_SYSRES (-1);
    }
  notify_table[i].fd = fd;
  notify_table[i].handler = handler;
  notify_table[i].value = value;
  notify_table[i].inuse = 1;
  UNLOCK (notify_table_lock);
  return TRACE_SYSRES (0);
}


int
_gpgme_io_set_nonblocking (int fd)
{
  TRACE (DEBUG_SYSIO, "_gpgme_io_set_nonblocking", fd);
  return 0;
}


#ifdef HAVE_W32CE_SYSTEM
static char *
build_commandline (char **argv, int fd0, int fd0_isnull,
		   int fd1, int fd1_isnull,
		   int fd2, int fd2_isnull)
{
  int i, n;
  const char *s;
  char *buf, *p;
  char fdbuf[3*30];

  p = fdbuf;
  *p = 0;

  if (fd0 != -1)
    {
      if (fd0_isnull)
        strcpy (p, "-&S0=null ");
      else
	snprintf (p, 25, "-&S0=%d ", fd_table[fd0].rvid);
      p += strlen (p);
    }
  if (fd1 != -1)
    {
      if (fd1_isnull)
        strcpy (p, "-&S1=null ");
      else
	snprintf (p, 25, "-&S1=%d ", fd_table[fd1].rvid);
      p += strlen (p);
    }
  if (fd2 != -1)
    {
      if (fd2_isnull)
        strcpy (p, "-&S2=null ");
      else
        snprintf (p, 25, "-&S2=%d ", fd_table[fd2].rvid);
      p += strlen (p);
    }
  strcpy (p, "-&S2=null ");
  p += strlen (p);

  n = strlen (fdbuf);
  for (i=0; (s = argv[i]); i++)
    {
      if (!i)
        continue; /* Ignore argv[0].  */
      n += strlen (s) + 1 + 2;  /* (1 space, 2 quoting) */
      for (; *s; s++)
        if (*s == '\"')
          n++;  /* Need to double inner quotes.  */
    }
  n++;
  buf = p = malloc (n);
  if (! buf)
    return NULL;

  p = stpcpy (p, fdbuf);
  for (i = 0; argv[i]; i++)
    {
      if (!i)
        continue; /* Ignore argv[0].  */
      if (i > 1)
        p = stpcpy (p, " ");

      if (! *argv[i]) /* Empty string. */
        p = stpcpy (p, "\"\"");
      else if (strpbrk (argv[i], " \t\n\v\f\""))
        {
          p = stpcpy (p, "\"");
          for (s = argv[i]; *s; s++)
            {
              *p++ = *s;
              if (*s == '\"')
                *p++ = *s;
            }
          *p++ = '\"';
          *p = 0;
        }
      else
        p = stpcpy (p, argv[i]);
    }

  return buf;
}
#else
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
#endif


int
_gpgme_io_spawn (const char *path, char *const argv[], unsigned int flags,
		 struct spawn_fd_item_s *fd_list,
		 void (*atfork) (void *opaque, int reserved),
		 void *atforkvalue, pid_t *r_pid)
{
  PROCESS_INFORMATION pi =
    {
      NULL,      /* returns process handle */
      0,         /* returns primary thread handle */
      0,         /* returns pid */
      0          /* returns tid */
    };
  int i;

#ifdef HAVE_W32CE_SYSTEM
  int fd_in = -1;
  int fd_out = -1;
  int fd_err = -1;
  int fd_in_isnull = 1;
  int fd_out_isnull = 1;
  int fd_err_isnull = 1;
  char *cmdline;
  HANDLE hd = INVALID_HANDLE_VALUE;

  TRACE_BEG1 (DEBUG_SYSIO, "_gpgme_io_spawn", path,
	      "path=%s", path);
  i = 0;
  while (argv[i])
    {
      TRACE_LOG2 ("argv[%2i] = %s", i, argv[i]);
      i++;
    }

  for (i = 0; fd_list[i].fd != -1; i++)
    {
      int fd = fd_list[i].fd;

      TRACE_LOG3 ("fd_list[%2i] = fd %i, dup_to %i", i, fd, fd_list[i].dup_to);
      if (fd < 0 || fd >= MAX_SLAFD || !fd_table[fd].used)
	{
	  TRACE_LOG1 ("invalid fd 0x%x", fd);
	  gpg_err_set_errno (EBADF);
	  return TRACE_SYSRES (-1);
	}
      if (fd_table[fd].rvid == 0)
	{
	  TRACE_LOG1 ("fd 0x%x not inheritable (not an RVID)", fd);
	  gpg_err_set_errno (EBADF);
	  return TRACE_SYSRES (-1);
	}

      if (fd_list[i].dup_to == 0)
	{
	  fd_in = fd_list[i].fd;
	  fd_in_isnull = 0;
	}
      else if (fd_list[i].dup_to == 1)
	{
	  fd_out = fd_list[i].fd;
	  fd_out_isnull = 0;
	}
      else if (fd_list[i].dup_to == 2)
	{
	  fd_err = fd_list[i].fd;
	  fd_err_isnull = 0;
	}
    }

  cmdline = build_commandline (argv, fd_in, fd_in_isnull,
			       fd_out, fd_out_isnull, fd_err, fd_err_isnull);
  if (!cmdline)
    {
      TRACE_LOG1 ("build_commandline failed: %s", strerror (errno));
      return TRACE_SYSRES (-1);
    }

  if (!CreateProcessA (path,                /* Program to start.  */
		       cmdline,             /* Command line arguments.  */
		       NULL,                 /* (not supported)  */
		       NULL,                 /* (not supported)  */
		       FALSE,                /* (not supported)  */
		       (CREATE_SUSPENDED),   /* Creation flags.  */
		       NULL,                 /* (not supported)  */
		       NULL,                 /* (not supported)  */
		       NULL,                 /* (not supported) */
		       &pi                   /* Returns process information.*/
		       ))
    {
      TRACE_LOG1 ("CreateProcess failed: ec=%d", (int) GetLastError ());
      free (cmdline);
      gpg_err_set_errno (EIO);
      return TRACE_SYSRES (-1);
    }

  /* Create arbitrary pipe descriptor to send in ASSIGN_RVID
     commands.  Errors are ignored.  We don't need read or write access,
     as ASSIGN_RVID works without any permissions, yay!  */
  hd = CreateFile (L"GPG1:", 0, 0,
		   NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hd == INVALID_HANDLE_VALUE)
    {
      TRACE_LOG1 ("CreateFile failed (ignored): ec=%d",
		  (int) GetLastError ());
    }

  /* Insert the inherited handles.  */
  for (i = 0; fd_list[i].fd != -1; i++)
    {
      /* Return the child name of this handle.  */
      fd_list[i].peer_name = fd_table[fd_list[i].fd].rvid;

      if (hd != INVALID_HANDLE_VALUE)
	{
	  DWORD data[2];
	  data[0] = (DWORD) fd_table[fd_list[i].fd].rvid;
	  data[1] = pi.dwProcessId;
	  if (!DeviceIoControl (hd, GPGCEDEV_IOCTL_ASSIGN_RVID,
				data, sizeof (data), NULL, 0, NULL, NULL))
	    {
	      TRACE_LOG3 ("ASSIGN_RVID(%i, %i) failed (ignored): %i",
			  data[0], data[1], (int) GetLastError ());
	    }
	}
    }
  if (hd != INVALID_HANDLE_VALUE)
    CloseHandle (hd);

#else
  SECURITY_ATTRIBUTES sec_attr;
  STARTUPINFOA si;
  int cr_flags = CREATE_DEFAULT_ERROR_MODE;
  char **args;
  char *arg_string;
  /* FIXME.  */
  int debug_me = 0;
  int tmp_fd;
  char *tmp_name;
  const char *spawnhelper;

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

  args = calloc (2 + i + 1, sizeof (*args));
  args[0] = (char *) _gpgme_get_w32spawn_path ();
  args[1] = tmp_name;
  args[2] = (char *)path;
  memcpy (&args[3], &argv[1], i * sizeof (*args));

  memset (&sec_attr, 0, sizeof sec_attr);
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = FALSE;

  arg_string = build_commandline (args);
  free (args);
  if (!arg_string)
    {
      close (tmp_fd);
      DeleteFileA (tmp_name);
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
  cr_flags |= GetPriorityClass (GetCurrentProcess ());
  spawnhelper = _gpgme_get_w32spawn_path ();
  if (!spawnhelper)
    {
      /* This is a common mistake for new users of gpgme not to include
         gpgme-w32spawn.exe with their binary. So we want to make
         this transparent to developers. If users have somehow messed
         up their installation this should also be properly communicated
         as otherwise calls to gnupg will result in unsupported protocol
         errors that do not explain a lot. */
      char *msg;
      gpgrt_asprintf (&msg, "gpgme-w32spawn.exe was not found in the "
                            "detected installation directory of GpgME"
                            "\n\t\"%s\"\n\n"
                            "Crypto operations will not work.\n\n"
                            "If you see this it indicates a problem "
                            "with your installation.\n"
                            "Please report the problem to your "
                            "distributor of GpgME.\n\n"
                            "Developers Note: The install dir can be "
                            "manually set with: gpgme_set_global_flag",
                            _gpgme_get_inst_dir ());
      MessageBoxA (NULL, msg, "GpgME not installed correctly", MB_OK);
      free (msg);
      gpg_err_set_errno (EIO);
      return TRACE_SYSRES (-1);
    }
  if (!CreateProcessA (spawnhelper,
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
      int lasterr = (int)GetLastError ();
      TRACE_LOG1 ("CreateProcess failed: ec=%d", lasterr);
      free (arg_string);
      close (tmp_fd);
      DeleteFileA (tmp_name);

      /* FIXME: Should translate the error code.  */
      gpg_err_set_errno (EIO);
      return TRACE_SYSRES (-1);
    }

  free (arg_string);

  if (flags & IOSPAWN_FLAG_ALLOW_SET_FG)
    _gpgme_allow_set_foreground_window ((pid_t)pi.dwProcessId);

  /* Insert the inherited handles.  */
  for (i = 0; fd_list[i].fd != -1; i++)
    {
      int fd = fd_list[i].fd;
      HANDLE ohd = INVALID_HANDLE_VALUE;
      HANDLE hd = INVALID_HANDLE_VALUE;

      /* Make it inheritable for the wrapper process.  */
      if (fd >= 0 && fd < MAX_SLAFD && fd_table[fd].used)
	ohd = fd_table[fd].handle;

      if (!DuplicateHandle (GetCurrentProcess(), ohd,
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
	  DeleteFileA (tmp_name);

	  /* FIXME: Should translate the error code.  */
	  gpg_err_set_errno (EIO);
	  return TRACE_SYSRES (-1);
        }
      /* Return the child name of this handle.  */
      fd_list[i].peer_name = handle_to_fd (hd);
    }

  /* Write the handle translation information to the temporary
     file.  */
  {
    /* Hold roughly MAX_TRANS quadruplets of 64 bit numbers in hex
       notation: "0xFEDCBA9876543210" with an extra white space after
       every quadruplet.  10*(19*4 + 1) - 1 = 769.  This plans ahead
       for a time when a HANDLE is 64 bit.  */
#define BUFFER_MAX 810
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
#endif


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

  if (! (flags & IOSPAWN_FLAG_NOCLOSE))
    {
      for (i = 0; fd_list[i].fd != -1; i++)
	_gpgme_io_close (fd_list[i].fd);
    }

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
  HANDLE waitbuf[MAXIMUM_WAIT_OBJECTS];
  int waitidx[MAXIMUM_WAIT_OBJECTS];
  int code;
  int nwait;
  int i;
  int any;
  int count;
  void *dbg_help;
  TRACE_BEG2 (DEBUG_SYSIO, "_gpgme_io_select", fds,
	      "nfds=%u, nonblock=%u", nfds, nonblock);

#if 0
 restart:
#endif
  TRACE_SEQ (dbg_help, "select on [ ");
  any = 0;
  nwait = 0;
  count = 0;
  for (i=0; i < nfds; i++)
    {
      if (fds[i].fd == -1)
	continue;
      fds[i].signaled = 0;
      if (fds[i].for_read || fds[i].for_write)
	{
	  if (fds[i].for_read)
	    {
	      struct reader_context_s *ctx = find_reader (fds[i].fd,1);

	      if (!ctx)
		TRACE_LOG1 ("error: no reader for FD 0x%x (ignored)",
			    fds[i].fd);
	      else
		{
		  if (nwait >= DIM (waitbuf))
		    {
		      TRACE_END (dbg_help, "oops ]");
		      TRACE_LOG ("Too many objects for WFMO!");
		      /* FIXME: Should translate the error code.  */
		      gpg_err_set_errno (EIO);
		      return TRACE_SYSRES (-1);
                    }
		  waitidx[nwait] = i;
		  waitbuf[nwait++] = ctx->have_data_ev;
                }
	      TRACE_ADD1 (dbg_help, "r0x%x ", fds[i].fd);
	      any = 1;
            }
	  else if (fds[i].for_write)
	    {
	      struct writer_context_s *ctx = find_writer (fds[i].fd,1);

	      if (!ctx)
		TRACE_LOG1 ("error: no writer for FD 0x%x (ignored)",
			    fds[i].fd);
	      else
		{
		  if (nwait >= DIM (waitbuf))
		    {
		      TRACE_END (dbg_help, "oops ]");
		      TRACE_LOG ("Too many objects for WFMO!");
		      /* FIXME: Should translate the error code.  */
		      gpg_err_set_errno (EIO);
		      return TRACE_SYSRES (-1);
                    }
		  waitidx[nwait] = i;
		  waitbuf[nwait++] = ctx->is_empty;
                }
	      TRACE_ADD1 (dbg_help, "w0x%x ", fds[i].fd);
	      any = 1;
            }
        }
    }
  TRACE_END (dbg_help, "]");
  if (!any)
    return TRACE_SYSRES (0);

  code = WaitForMultipleObjects (nwait, waitbuf, 0, nonblock ? 0 : 1000);
  if (code >= WAIT_OBJECT_0 && code < WAIT_OBJECT_0 + nwait)
    {
      /* This WFMO is a really silly function: It does return either
	 the index of the signaled object or if 2 objects have been
	 signalled at the same time, the index of the object with the
	 lowest object is returned - so and how do we find out how
	 many objects have been signaled???.  The only solution I can
	 imagine is to test each object starting with the returned
	 index individually - how dull.  */
      any = 0;
      for (i = code - WAIT_OBJECT_0; i < nwait; i++)
	{
	  if (WaitForSingleObject (waitbuf[i], 0) == WAIT_OBJECT_0)
	    {
	      assert (waitidx[i] >=0 && waitidx[i] < nfds);
	      fds[waitidx[i]].signaled = 1;
	      any = 1;
	      count++;
	    }
	}
      if (!any)
	{
	  TRACE_LOG ("no signaled objects found after WFMO");
	  count = -1;
	}
    }
  else if (code == WAIT_TIMEOUT)
    TRACE_LOG ("WFMO timed out");
  else if (code == WAIT_FAILED)
    {
      int le = (int) GetLastError ();
#if 0
      if (le == ERROR_INVALID_HANDLE)
	{
	  int k;
	  int j = handle_to_fd (waitbuf[i]);

	  TRACE_LOG1 ("WFMO invalid handle %d removed", j);
	  for (k = 0 ; k < nfds; k++)
	    {
	      if (fds[k].fd == j)
		{
		  fds[k].for_read = fds[k].for_write = 0;
		  goto restart;
                }
            }
	  TRACE_LOG (" oops, or not???");
        }
#endif
      TRACE_LOG1 ("WFMO failed: %d", le);
      count = -1;
    }
  else
    {
      TRACE_LOG1 ("WFMO returned %d", code);
      count = -1;
    }

  if (count > 0)
    {
      TRACE_SEQ (dbg_help, "select OK [ ");
      for (i = 0; i < nfds; i++)
	{
	  if (fds[i].fd == -1)
	    continue;
	  if ((fds[i].for_read || fds[i].for_write) && fds[i].signaled)
	    TRACE_ADD2 (dbg_help, "%c0x%x ",
			fds[i].for_read ? 'r' : 'w', fds[i].fd);
        }
      TRACE_END (dbg_help, "]");
    }

  if (count < 0)
    {
      /* FIXME: Should determine a proper error code.  */
      gpg_err_set_errno (EIO);
    }

  return TRACE_SYSRES (count);
}


void
_gpgme_io_subsystem_init (void)
{
  /* Nothing to do.  */
}


/* Write the printable version of FD to the buffer BUF of length
   BUFLEN.  The printable version is the representation on the command
   line that the child process expects.  */
int
_gpgme_io_fd2str (char *buf, int buflen, int fd)
{
#ifdef HAVE_W32CE_SYSTEM
  /* FIXME: For now. See above.  */
  if (fd < 0 || fd >= MAX_SLAFD || !fd_table[fd].used
      || fd_table[fd].rvid == 0)
    fd = -1;
  else
    fd = fd_table[fd].rvid;
#endif

  return snprintf (buf, buflen, "%d", fd);
}


int
_gpgme_io_dup (int fd)
{
  int newfd;
  struct reader_context_s *rd_ctx;
  struct writer_context_s *wt_ctx;
  int i;

  TRACE_BEG (DEBUG_SYSIO, "_gpgme_io_dup", fd);

  if (fd < 0 || fd >= MAX_SLAFD || !fd_table[fd].used)
    {
      gpg_err_set_errno (EINVAL);
      return TRACE_SYSRES (-1);
    }

  newfd = new_fd();
  if (newfd == -1)
    return TRACE_SYSRES (-1);

  fd_table[newfd].handle = fd_table[fd].handle;
  fd_table[newfd].socket = fd_table[fd].socket;
  fd_table[newfd].rvid = fd_table[fd].rvid;
  fd_table[newfd].dup_from = fd;

  rd_ctx = find_reader (fd, 1);
  if (rd_ctx)
    {
      /* No need for locking, as the only races are against the reader
	 thread itself, which doesn't touch refcount.  */
      rd_ctx->refcount++;

      LOCK (reader_table_lock);
      for (i = 0; i < reader_table_size; i++)
	if (!reader_table[i].used)
	  break;
      /* FIXME.  */
      assert (i != reader_table_size);
      reader_table[i].fd = newfd;
      reader_table[i].context = rd_ctx;
      reader_table[i].used = 1;
      UNLOCK (reader_table_lock);
    }

  wt_ctx = find_writer (fd, 1);
  if (wt_ctx)
    {
      /* No need for locking, as the only races are against the writer
	 thread itself, which doesn't touch refcount.  */
      wt_ctx->refcount++;

      LOCK (writer_table_lock);
      for (i = 0; i < writer_table_size; i++)
	if (!writer_table[i].used)
	  break;
      /* FIXME.  */
      assert (i != writer_table_size);
      writer_table[i].fd = newfd;
      writer_table[i].context = wt_ctx;
      writer_table[i].used = 1;
      UNLOCK (writer_table_lock);
    }

  return TRACE_SYSRES (newfd);
}


/* The following interface is only useful for GPGME Glib and Qt.  */

/* Compatibility interface, obsolete.  */
void *
gpgme_get_giochannel (int fd)
{
  return NULL;
}


/* Look up the giochannel or qiodevice for file descriptor FD.  */
void *
gpgme_get_fdptr (int fd)
{
  return NULL;
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

  TRACE_BEG2 (DEBUG_SYSIO, "_gpgme_io_socket", domain,
	      "type=%i, protp=%i", type, proto);

  fd = new_fd();
  if (fd == -1)
    return TRACE_SYSRES (-1);

  res = socket (domain, type, proto);
  if (res == INVALID_SOCKET)
    {
      release_fd (fd);
      gpg_err_set_errno (wsa2errno (WSAGetLastError ()));
      return TRACE_SYSRES (-1);
    }
  fd_table[fd].socket = res;

  TRACE_SUC2 ("socket=0x%x (0x%x)", fd, fd_table[fd].socket);

  return fd;
}


int
_gpgme_io_connect (int fd, struct sockaddr *addr, int addrlen)
{
  int res;

  TRACE_BEG2 (DEBUG_SYSIO, "_gpgme_io_connect", fd,
	      "addr=%p, addrlen=%i", addr, addrlen);

  if (fd < 0 || fd >= MAX_SLAFD || !fd_table[fd].used)
    {
      gpg_err_set_errno (EBADF);
      return TRACE_SYSRES (-1);
    }

  res = connect (fd_table[fd].socket, addr, addrlen);
  if (res)
    {
      gpg_err_set_errno (wsa2errno (WSAGetLastError ()));
      return TRACE_SYSRES (-1);
    }

  return TRACE_SUC ();
}
