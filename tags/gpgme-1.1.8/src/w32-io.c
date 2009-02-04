/* w32-io.c - W32 API I/O functions.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004, 2007 g10 Code GmbH

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
#include <sys/time.h>
#include <sys/types.h>
#include <windows.h>
#include <io.h>

#include "util.h"
#include "sema.h"
#include "priv-io.h"
#include "debug.h"


/* We assume that a HANDLE can be represented by an int which should
   be true for all i386 systems (HANDLE is defined as void *) and
   these are the only systems for which Windows is available.  Further
   we assume that -1 denotes an invalid handle.  */

#define fd_to_handle(a)  ((HANDLE)(a))
#define handle_to_fd(a)  ((int)(a))
#define pid_to_handle(a) ((HANDLE)(a))
#define handle_to_pid(a) ((int)(a))

#define READBUF_SIZE 4096
#define WRITEBUF_SIZE 4096
#define PIPEBUF_SIZE  4096
#define MAX_READERS 20
#define MAX_WRITERS 20

static struct
{
  int inuse;
  int fd;
  _gpgme_close_notify_handler_t handler;
  void *value;
} notify_table[256];
DEFINE_STATIC_LOCK (notify_table_lock);


struct reader_context_s
{
  HANDLE file_hd;
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
  HANDLE stopped;
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
  HANDLE thread_hd;	
  int refcount;

  DECLARE_LOCK (mutex);
  
  int stop_me;
  int error;
  int error_code;

  /* This is manually reset.  */
  HANDLE have_data;
  HANDLE is_empty;
  HANDLE stopped;
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
      errno = EIO;
      return INVALID_HANDLE_VALUE;
    }

  CloseHandle (hd);
  return new_hd;
}


static DWORD CALLBACK 
reader (void *arg)
{
  struct reader_context_s *ctx = arg;
  int nbytes;
  DWORD nread;
  TRACE_BEG1 (DEBUG_SYSIO, "gpgme:reader", ctx->file_hd,
	      "thread=%p", ctx->thread_hd);

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
      
      TRACE_LOG1 ("reading %d bytes", nbytes);
      if (!ReadFile (ctx->file_hd,
		     ctx->buffer + ctx->writepos, nbytes, &nread, NULL))
	{
	  ctx->error_code = (int) GetLastError ();
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
      if (!nread)
	{
	  ctx->eof = 1;
	  TRACE_LOG ("got eof");
	  break;
        }
      TRACE_LOG1 ("got %u bytes", nread);
      
      LOCK (ctx->mutex);
      if (ctx->stop_me)
	{
	  UNLOCK (ctx->mutex);
	  break;
        }
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
  SetEvent (ctx->stopped);
  
  return TRACE_SUC ();
}


static struct reader_context_s *
create_reader (HANDLE fd)
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

  ctx->file_hd = fd;
  ctx->refcount = 1;
  ctx->have_data_ev = CreateEvent (&sec_attr, TRUE, FALSE, NULL);
  if (ctx->have_data_ev)
    ctx->have_space_ev = CreateEvent (&sec_attr, FALSE, TRUE, NULL);
  if (ctx->have_space_ev)
    ctx->stopped = CreateEvent (&sec_attr, TRUE, FALSE, NULL);
  if (!ctx->have_data_ev || !ctx->have_space_ev || !ctx->stopped)
    {
      TRACE_LOG1 ("CreateEvent failed: ec=%d", (int) GetLastError ());
      if (ctx->have_data_ev)
	CloseHandle (ctx->have_data_ev);
      if (ctx->have_space_ev)
	CloseHandle (ctx->have_space_ev);
      if (ctx->stopped)
	CloseHandle (ctx->stopped);
      free (ctx);
      /* FIXME: Translate the error code.  */
      TRACE_SYSERR (EIO);
      return NULL;
    }

  ctx->have_data_ev = set_synchronize (ctx->have_data_ev);
  INIT_LOCK (ctx->mutex);

  ctx->thread_hd = CreateThread (&sec_attr, 0, reader, ctx, 0, &tid);
  if (!ctx->thread_hd)
    {
      TRACE_LOG1 ("CreateThread failed: ec=%d", (int) GetLastError ());
      DESTROY_LOCK (ctx->mutex);
      if (ctx->have_data_ev)
	CloseHandle (ctx->have_data_ev);
      if (ctx->have_space_ev)
	CloseHandle (ctx->have_space_ev);
      if (ctx->stopped)
	CloseHandle (ctx->stopped);
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

  TRACE1 (DEBUG_SYSIO, "gpgme:destroy_reader", ctx->file_hd,
	  "waiting for termination of thread %p", ctx->thread_hd);
  WaitForSingleObject (ctx->stopped, INFINITE);
  TRACE1 (DEBUG_SYSIO, "gpgme:destroy_reader", ctx->file_hd,
	  "thread %p has terminated", ctx->thread_hd);
    
  if (ctx->stopped)
    CloseHandle (ctx->stopped);
  if (ctx->have_data_ev)
    CloseHandle (ctx->have_data_ev);
  if (ctx->have_space_ev)
    CloseHandle (ctx->have_space_ev);
  CloseHandle (ctx->thread_hd);
  DESTROY_LOCK (ctx->mutex);
  free (ctx);
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
      rd = create_reader (fd_to_handle (fd));
      reader_table[i].fd = fd;
      reader_table[i].context = rd;
      reader_table[i].used = 1;
    }

  UNLOCK (reader_table_lock);
  return rd;
}


static void
kill_reader (int fd)
{
  int i;

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
      errno = EBADF;
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
      errno = ctx->error_code;
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
	  errno = EIO;
	  return TRACE_SYSRES (-1);
	}
    }
  if (!SetEvent (ctx->have_space_ev))
    {
      TRACE_LOG2 ("SetEvent (0x%x) failed: ec=%d",
		  ctx->have_space_ev, (int) GetLastError ());
      UNLOCK (ctx->mutex);
      /* FIXME: Should translate the error code.  */
      errno = EIO;
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
  TRACE_BEG1 (DEBUG_SYSIO, "gpgme:writer", ctx->file_hd,
	      "thread=%p", ctx->thread_hd);

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
      
      TRACE_LOG1 ("writing %d bytes", ctx->nbytes);
      /* Note that CTX->nbytes is not zero at this point, because
	 _gpgme_io_write always writes at least 1 byte before waking
	 us up, unless CTX->stop_me is true, which we catch above.  */
      if (!WriteFile (ctx->file_hd, ctx->buffer,
		      ctx->nbytes, &nwritten, NULL))
	{
	  ctx->error_code = (int) GetLastError ();
	  ctx->error = 1;
	  TRACE_LOG1 ("write error: ec=%d", ctx->error_code);
	  break;
	}
      TRACE_LOG1 ("wrote %d bytes", (int) nwritten);
      
      LOCK (ctx->mutex);
      ctx->nbytes -= nwritten;
      UNLOCK (ctx->mutex);
    }
  /* Indicate that we have an error.  */
  if (!SetEvent (ctx->is_empty))
    TRACE_LOG1 ("SetEvent failed: ec=%d", (int) GetLastError ());
  SetEvent (ctx->stopped);

  return TRACE_SUC ();
}


static struct writer_context_s *
create_writer (HANDLE fd)
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
  
  ctx->file_hd = fd;
  ctx->refcount = 1;
  ctx->have_data = CreateEvent (&sec_attr, TRUE, FALSE, NULL);
  if (ctx->have_data)
    ctx->is_empty  = CreateEvent (&sec_attr, TRUE, TRUE, NULL);
  if (ctx->is_empty)
    ctx->stopped = CreateEvent (&sec_attr, TRUE, FALSE, NULL);
  if (!ctx->have_data || !ctx->is_empty || !ctx->stopped)
    {
      TRACE_LOG1 ("CreateEvent failed: ec=%d", (int) GetLastError ());
      if (ctx->have_data)
	CloseHandle (ctx->have_data);
      if (ctx->is_empty)
	CloseHandle (ctx->is_empty);
      if (ctx->stopped)
	CloseHandle (ctx->stopped);
      free (ctx);
      /* FIXME: Translate the error code.  */
      TRACE_SYSERR (EIO);
      return NULL;
    }

  ctx->is_empty = set_synchronize (ctx->is_empty);
  INIT_LOCK (ctx->mutex);

  ctx->thread_hd = CreateThread (&sec_attr, 0, writer, ctx, 0, &tid );
  if (!ctx->thread_hd)
    {
      TRACE_LOG1 ("CreateThread failed: ec=%d", (int) GetLastError ());
      DESTROY_LOCK (ctx->mutex);
      if (ctx->have_data)
	CloseHandle (ctx->have_data);
      if (ctx->is_empty)
	CloseHandle (ctx->is_empty);
      if (ctx->stopped)
	CloseHandle (ctx->stopped);
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
  
  TRACE1 (DEBUG_SYSIO, "gpgme:destroy_writer", ctx->file_hd,
	  "waiting for termination of thread %p", ctx->thread_hd);
  WaitForSingleObject (ctx->stopped, INFINITE);
  TRACE1 (DEBUG_SYSIO, "gpgme:destroy_writer", ctx->file_hd,
	  "thread %p has terminated", ctx->thread_hd);
  
  if (ctx->stopped)
    CloseHandle (ctx->stopped);
  if (ctx->have_data)
    CloseHandle (ctx->have_data);
  if (ctx->is_empty)
    CloseHandle (ctx->is_empty);
  CloseHandle (ctx->thread_hd);
  DESTROY_LOCK (ctx->mutex);
  free (ctx);
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
      wt = create_writer (fd_to_handle (fd));
      writer_table[i].fd = fd;
      writer_table[i].context = wt; 
      writer_table[i].used = 1;
    }

  UNLOCK (writer_table_lock);
  return wt;
}


static void
kill_writer (int fd)
{
  int i;

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
	  errno = EIO;
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
        errno = EPIPE;
      else
        errno = EIO;
      return TRACE_SYSRES (-1);
    }

  /* If no error occured, the number of bytes in the buffer must be
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
      errno = EIO;
      return TRACE_SYSRES (-1);
    }
  if (!SetEvent (ctx->have_data))
    {
      TRACE_LOG1 ("SetEvent failed: ec=%d", (int) GetLastError ());
      UNLOCK (ctx->mutex);
      /* FIXME: Should translate the error code.  */
      errno = EIO;
      return TRACE_SYSRES (-1);
    }
  UNLOCK (ctx->mutex);

  return TRACE_SYSRES ((int) count);
}


int
_gpgme_io_pipe (int filedes[2], int inherit_idx)
{
  HANDLE rh;
  HANDLE wh;
  SECURITY_ATTRIBUTES sec_attr;
  TRACE_BEG2 (DEBUG_SYSIO, "_gpgme_io_pipe", filedes,
	      "inherit_idx=%i (GPGME uses it for %s)",
	      inherit_idx, inherit_idx ? "reading" : "writing");

  memset (&sec_attr, 0, sizeof (sec_attr));
  sec_attr.nLength = sizeof (sec_attr);
  sec_attr.bInheritHandle = FALSE;
  
  if (!CreatePipe (&rh, &wh, &sec_attr, PIPEBUF_SIZE))
    {
      TRACE_LOG1 ("CreatePipe failed: ec=%d", (int) GetLastError ());
      /* FIXME: Should translate the error code.  */
      errno = EIO;
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
	  CloseHandle (rh);
	  CloseHandle (wh);
	  /* FIXME: Should translate the error code.  */
	  errno = EIO;
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
	  CloseHandle (rh);
	  CloseHandle (wh);
	  /* FIXME: Should translate the error code.  */
	  errno = EIO;
	  return TRACE_SYSRES (-1);
        }
      CloseHandle (wh);
      wh = hd;
    }
  
  filedes[0] = handle_to_fd (rh);
  filedes[1] = handle_to_fd (wh);
  return TRACE_SUC2 ("read=%p, write=%p", rh, wh);
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
      errno = EBADF;
      return TRACE_SYSRES (-1);
    }

  kill_reader (fd);
  kill_writer (fd);
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

  if (!CloseHandle (fd_to_handle (fd)))
    { 
      TRACE_LOG1 ("CloseHandle failed: ec=%d", (int) GetLastError ());
      /* FIXME: Should translate the error code.  */
      errno = EIO;
      return TRACE_SYSRES (-1);
    }

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
      errno = EINVAL;
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
_gpgme_io_spawn (const char *path, char *const argv[],
		 struct spawn_fd_item_s *fd_list, pid_t *r_pid)
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

  /* Insert the inherited handles.  */
  for (i = 0; fd_list[i].fd != -1; i++)
    {
      HANDLE hd;

      /* Make it inheritable for the wrapper process.  */
      if (!DuplicateHandle (GetCurrentProcess(), fd_to_handle (fd_list[i].fd),
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
      fd_list[i].peer_name = handle_to_fd (hd);
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

    line[0] = '\n';
    line[1] = '\0';
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

 restart:
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
		      errno = EIO;
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
		      errno = EIO;
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
      errno = EIO;
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
  return snprintf (buf, buflen, "%d", fd);
}


int
_gpgme_io_dup (int fd)
{
  HANDLE handle = fd_to_handle (fd);
  HANDLE new_handle = fd_to_handle (fd);
  int i;
  struct reader_context_s *rd_ctx;
  struct writer_context_s *wt_ctx;

  TRACE_BEG (DEBUG_SYSIO, "_gpgme_io_dup", fd);

  if (!DuplicateHandle (GetCurrentProcess(), handle,
			GetCurrentProcess(), &new_handle,
			0, FALSE, DUPLICATE_SAME_ACCESS))
    {
      TRACE_LOG1 ("DuplicateHandle failed: ec=%d\n", (int) GetLastError ());
      /* FIXME: Translate error code.  */
      errno = EIO;
      return TRACE_SYSRES (-1);
    }

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
      reader_table[i].fd = handle_to_fd (new_handle);
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
      writer_table[i].fd = handle_to_fd (new_handle);
      writer_table[i].context = wt_ctx;
      writer_table[i].used = 1;
      UNLOCK (writer_table_lock);
    }

  return TRACE_SYSRES (handle_to_fd (new_handle));
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
