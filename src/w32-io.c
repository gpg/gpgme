/* w32-io.c - W32 API I/O functions.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001-2004, 2007, 2010, 2018 g10 Code GmbH
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
 * SPDX-License-Identifier: LGPL-2.1+
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
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <io.h>

#include "util.h"
#include "sema.h"
#include "priv-io.h"
#include "debug.h"
#include "sys-util.h"


/* The number of entries in our file table.  We may eventually use a
 * lower value and dynamically resize the table.  */
#define MAX_SLAFD 512

#define READBUF_SIZE 4096
#define WRITEBUF_SIZE 4096
#define PIPEBUF_SIZE  4096


/* An object to store handles or sockets.  */
struct hddesc_s
{
  HANDLE hd;
  SOCKET sock;
  int refcount;
};
typedef struct hddesc_s *hddesc_t;



/* The context used by a reader thread.  */
struct reader_context_s
{
  hddesc_t hdd;
  HANDLE thread_hd;
  int refcount;   /* Bumped if the FD has been duped and thus we have
                   * another FD referencing this context.  */

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


/* The context used by a writer thread.  */
struct writer_context_s
{
  hddesc_t hdd;
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


/* An object to keep track of HANDLEs and sockets and map them to an
 * integer similar to what we use in Unix.  Note that despite this
 * integer is often named "fd", it is not a file descriptor but really
 * only an index into this table.  Never ever pass such an fd to any
 * other function except for those implemented here.  */
static struct
{
  int used;

  /* The handle descriptor.  */
  hddesc_t hdd;

  /* DUP_FROM is just a debug helper to show from which fd this fd was
   * dup-ed. */
  int dup_from;

  /* Two flags to indicate whether a reader or writer (or both) are
   * needed.  This is so that we can delay the actual thread creation
   * until they are needed.  */
  unsigned int want_reader:1;
  unsigned int want_writer:1;

  /* The context of an associated reader object or NULL.  */
  struct reader_context_s *reader;

  /* The context of an associated writer object or NULL.  */
  struct writer_context_s *writer;

  /* A notification handler.  Note that we currently support only one
   * callback per fd.  */
  struct {
    _gpgme_close_notify_handler_t handler;
    void *value;
  } notify;

} fd_table[MAX_SLAFD];
static size_t fd_table_size = MAX_SLAFD;

DEFINE_STATIC_LOCK (fd_table_lock);


/* We use a single global lock for all hddesc_t objects.  */
DEFINE_STATIC_LOCK (hddesc_lock);



/* Wrapper around CloseHandle to print an error.  */
#define close_handle(hd) _close_handle ((hd), __LINE__);
static void
_close_handle (HANDLE hd, int line)
{
  if (!CloseHandle (hd))
    {
      TRACE (DEBUG_INIT, "w32-io", hd, "CloseHandle failed at line %d: ec=%d",
              line, (int) GetLastError ());
    }
}

/* Wrapper around WaitForSingleObject to print an error.  */
#define wait_for_single_object(hd,msec) \
        _wait_for_single_object ((hd), (msec), __LINE__)
static DWORD
_wait_for_single_object (HANDLE hd, DWORD msec, int line)
{
  DWORD res;

  res = WaitForSingleObject (hd, msec);
  if (res == WAIT_FAILED)
    {
      TRACE (DEBUG_INIT, "w32-io", hd,
              "WFSO failed at line %d: ec=%d", line, (int) GetLastError ());
    }
  return res;
}


/* Create a new handle descriptor object.  */
static hddesc_t
new_hddesc (void)
{
  hddesc_t hdd;

  hdd = malloc (sizeof *hdd);
  if (!hdd)
    return NULL;
  hdd->hd = INVALID_HANDLE_VALUE;
  hdd->sock = INVALID_SOCKET;
  hdd->refcount = 0;

  return hdd;
}


static hddesc_t
ref_hddesc (hddesc_t hdd)
{
  LOCK (hddesc_lock);
  hdd->refcount++;
  UNLOCK (hddesc_lock);
  return hdd;
}


/* Release a handle descriptor object and close its handle or socket
 * if needed.  */
static void
release_hddesc (hddesc_t hdd)
{
  if (!hdd)
    return;

  LOCK (hddesc_lock);
  hdd->refcount--;
  if (hdd->refcount < 1)
    {
      /* Holds a valid handle or was never initialized (in which case
       * REFCOUNT would be -1 here).  */
      TRACE_BEG  (DEBUG_SYSIO, "gpgme:release_hddesc", hdd,
                  "hd=%p, sock=%p, refcount=%d",
                  hdd->hd, (void *)hdd->sock, hdd->refcount);

      if (hdd->hd != INVALID_HANDLE_VALUE)
        close_handle (hdd->hd);

      if (hdd->sock != INVALID_SOCKET)
        {
          TRACE_LOG  ("closing socket %p", (void *)hdd->sock);
          if (closesocket (hdd->sock))
            {
              TRACE_LOG  ("closesocket failed: ec=%d", (int)WSAGetLastError ());
            }
        }

      free (hdd);
      TRACE_SUC ("");
    }
  UNLOCK (hddesc_lock);
}



/* Returns our FD or -1 on resource limit.  The returned integer
 * references a new object which has not been initialized but can be
 * release with release_fd.  */
static int
new_fd (void)
{
  int idx;

  LOCK (fd_table_lock);

  for (idx = 0; idx < fd_table_size; idx++)
    if (! fd_table[idx].used)
      break;

  if (idx == fd_table_size)
    {
      gpg_err_set_errno (EIO);
      idx = -1;
    }
  else
    {
      fd_table[idx].used = 1;
      fd_table[idx].hdd = NULL;
      fd_table[idx].dup_from = -1;
      fd_table[idx].want_reader = 0;
      fd_table[idx].want_writer = 0;
      fd_table[idx].reader = NULL;
      fd_table[idx].writer = NULL;
      fd_table[idx].notify.handler = NULL;
      fd_table[idx].notify.value = NULL;
    }

  UNLOCK (fd_table_lock);

  return idx;
}


/* Releases our FD but it this is just this entry.  No close operation
 * is involved here; it must be done prior to calling this
 * function.  */
static void
release_fd (int fd)
{
  if (fd < 0 || fd >= fd_table_size)
    return;

  LOCK (fd_table_lock);

  if (fd_table[fd].used)
    {
      release_hddesc (fd_table[fd].hdd);
      fd_table[fd].used = 0;
      fd_table[fd].hdd = NULL;
      fd_table[fd].dup_from = -1;
      fd_table[fd].want_reader = 0;
      fd_table[fd].want_writer = 0;
      fd_table[fd].reader = NULL;
      fd_table[fd].writer = NULL;
      fd_table[fd].notify.handler = NULL;
      fd_table[fd].notify.value = NULL;
    }

  UNLOCK (fd_table_lock);
}


static int
get_desired_thread_priority (void)
{
  int value;

  if (!_gpgme_get_conf_int ("IOThreadPriority", &value))
    {
      value = THREAD_PRIORITY_HIGHEST;
      TRACE (DEBUG_SYSIO, "gpgme:get_desired_thread_priority", 0,
	      "%d (default)", value);
    }
  else
    {
      TRACE (DEBUG_SYSIO, "gpgme:get_desired_thread_priority", 0,
	      "%d (configured)", value);
    }
  return value;
}


/* The reader thread.  Created on the fly by gpgme_io_read and
 * destroyed by destroy_reader.  Note that this functions works with a
 * copy of the value of the HANDLE variable frm the FS_TABLE.  */
static DWORD CALLBACK
reader (void *arg)
{
  struct reader_context_s *ctx = arg;
  int nbytes;
  DWORD nread;
  int sock;

  TRACE_BEG  (DEBUG_SYSIO, "gpgme:reader", ctx->hdd,
	      "hd=%p, sock=%p, thread=%p, refcount=%d",
              ctx->hdd->hd, (void *)ctx->hdd->sock, ctx->thread_hd,
              ctx->refcount);

  if (ctx->hdd->hd != INVALID_HANDLE_VALUE)
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
            {
              TRACE_LOG  ("ResetEvent failed: ec=%d", (int) GetLastError ());
            }
	  UNLOCK (ctx->mutex);
	  TRACE_LOG  ("waiting for space (refcnt=%d)", ctx->refcount);
	  wait_for_single_object (ctx->have_space_ev, INFINITE);
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

      TRACE_LOG  ("%s %d bytes", sock? "receiving":"reading", nbytes);

      if (sock)
        {
          int n;

          n = recv (ctx->hdd->sock, ctx->buffer + ctx->writepos, nbytes, 0);
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
                     no need to print a warning in this case.  */
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
                  TRACE_LOG  ("recv error: ec=%d", ctx->error_code);
                }
              break;
            }
          nread = n;
        }
      else
        {
          if (!ReadFile (ctx->hdd->hd,
                         ctx->buffer + ctx->writepos, nbytes, &nread, NULL))
            {
              ctx->error_code = (int) GetLastError ();
              if (ctx->error_code == ERROR_BROKEN_PIPE)
                {
                  ctx->eof = 1;
                  TRACE_LOG ("got EOF (broken pipe)");
                }
              else if (ctx->error_code == ERROR_OPERATION_ABORTED)
                {
                  ctx->eof = 1;
                  TRACE_LOG ("got EOF (closed by us)");
                }
              else
                {
                  ctx->error = 1;
                  TRACE_LOG  ("read error: ec=%d", ctx->error_code);
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

      TRACE_LOG  ("got %lu bytes (refcnt=%d)", nread, ctx->refcount);

      ctx->writepos = (ctx->writepos + nread) % READBUF_SIZE;
      if (!SetEvent (ctx->have_data_ev))
        {
          TRACE_LOG  ("SetEvent (%p) failed: ec=%d", ctx->have_data_ev,
                      (int) GetLastError ());
        }
      UNLOCK (ctx->mutex);
    }
  /* Indicate that we have an error or EOF.  */
  if (!SetEvent (ctx->have_data_ev))
    {
      TRACE_LOG ("SetEvent (%p) failed: ec=%d", ctx->have_data_ev,
                (int) GetLastError ());
    }

  TRACE_LOG ("waiting for close");
  wait_for_single_object (ctx->close_ev, INFINITE);

  release_hddesc (ctx->hdd);
  close_handle (ctx->close_ev);
  close_handle (ctx->have_data_ev);
  close_handle (ctx->have_space_ev);
  close_handle (ctx->thread_hd);
  DESTROY_LOCK (ctx->mutex);
  free (ctx);

  TRACE_SUC ("");
  return 0;
}


/* Create a new reader thread and return its context object.  The
 * input is the handle descriptor HDD.  This function may not call any
 * fd based functions because the caller already holds a lock on the
 * fd_table.  */
static struct reader_context_s *
create_reader (hddesc_t hdd)
{
  struct reader_context_s *ctx;
  SECURITY_ATTRIBUTES sec_attr;
  DWORD tid;

  TRACE_BEG  (DEBUG_SYSIO, "gpgme:create_reader", hdd,
              "hd=%p sock=%p refcount=%d",
              hdd->hd, (void *)hdd->sock, hdd->refcount);

  memset (&sec_attr, 0, sizeof sec_attr);
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = FALSE;

  ctx = calloc (1, sizeof *ctx);
  if (!ctx)
    {
      TRACE_SYSERR (errno);
      return NULL;
    }

  ctx->hdd = ref_hddesc (hdd);

  ctx->refcount = 1;
  ctx->have_data_ev = CreateEvent (&sec_attr, TRUE, FALSE, NULL);
  if (ctx->have_data_ev)
    ctx->have_space_ev = CreateEvent (&sec_attr, FALSE, TRUE, NULL);
  if (ctx->have_space_ev)
    ctx->close_ev = CreateEvent (&sec_attr, TRUE, FALSE, NULL);
  if (!ctx->have_data_ev || !ctx->have_space_ev || !ctx->close_ev)
    {
      TRACE_LOG  ("CreateEvent failed: ec=%d", (int) GetLastError ());
      if (ctx->have_data_ev)
	close_handle (ctx->have_data_ev);
      if (ctx->have_space_ev)
	close_handle (ctx->have_space_ev);
      if (ctx->close_ev)
	close_handle (ctx->close_ev);
      release_hddesc (ctx->hdd);
      free (ctx);
      TRACE_SYSERR (EIO);
      return NULL;
    }

  INIT_LOCK (ctx->mutex);

  ctx->thread_hd = CreateThread (&sec_attr, 0, reader, ctx, 0, &tid);

  if (!ctx->thread_hd)
    {
      TRACE_LOG  ("CreateThread failed: ec=%d", (int) GetLastError ());
      DESTROY_LOCK (ctx->mutex);
      if (ctx->have_data_ev)
	close_handle (ctx->have_data_ev);
      if (ctx->have_space_ev)
	close_handle (ctx->have_space_ev);
      if (ctx->close_ev)
	close_handle (ctx->close_ev);
      release_hddesc (ctx->hdd);
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

  TRACE_SUC ("");
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
      TRACE (DEBUG_SYSIO, "gpgme:destroy_reader", ctx,
              "hdd=%p refcount now %d", ctx->hdd, ctx->refcount);
      UNLOCK (ctx->mutex);
      return;
    }
  ctx->stop_me = 1;
  if (ctx->have_space_ev)
    SetEvent (ctx->have_space_ev);
  TRACE (DEBUG_SYSIO, "gpgme:destroy_reader", ctx,
          "hdd=%p close triggered", ctx->hdd);
  UNLOCK (ctx->mutex);

  /* The reader thread is usually blocking in recv or ReadFile.  If
     the peer does not send an EOF or breaks the pipe the WFSO might
     get stuck waiting for the termination of the reader thread.  This
     happens quite often with sockets, thus we definitely need to get
     out of the recv.  A shutdown does this nicely.  For handles
     (i.e. pipes) it would also be nice to cancel the operation, but
     such a feature is only available since Vista.  Thus we need to
     dlopen that syscall.  */
  assert (ctx->hdd);
  if (ctx->hdd && ctx->hdd->hd != INVALID_HANDLE_VALUE)
    {
      _gpgme_w32_cancel_synchronous_io (ctx->thread_hd);
    }
  else if (ctx->hdd && ctx->hdd->sock != INVALID_SOCKET)
    {
      if (shutdown (ctx->hdd->sock, 2))
        TRACE (DEBUG_SYSIO, "gpgme:destroy_reader", ctx,
                "shutdown socket %p failed: ec=%d",
                (void *)ctx->hdd->sock, (int) WSAGetLastError ());
    }

  /* After setting this event CTX is void. */
  SetEvent (ctx->close_ev);
}



/* Find a reader context or create a new one.  Note that the reader
 * context will last until a _gpgme_io_close.  NULL is returned for a
 * bad FD or for other errors.  */
static struct reader_context_s *
find_reader (int fd)
{
  struct reader_context_s *rd = NULL;

  TRACE_BEG (DEBUG_SYSIO, "gpgme:find_reader", fd, "");

  LOCK (fd_table_lock);
  if (fd < 0 || fd >= fd_table_size || !fd_table[fd].used)
    {
      UNLOCK (fd_table_lock);
      gpg_err_set_errno (EBADF);
      TRACE_SUC ("EBADF");
      return NULL;
    }

  rd = fd_table[fd].reader;
  if (rd)
    {
      UNLOCK (fd_table_lock);
      TRACE_SUC ("rd=%p", rd);
      return rd;  /* Return already initialized reader thread object.  */
    }

  /* Create a new reader thread.  */
  TRACE_LOG  ("fd=%d -> hdd=%p dupfrom=%d creating reader",
              fd, fd_table[fd].hdd, fd_table[fd].dup_from);
  rd = create_reader (fd_table[fd].hdd);
  if (!rd)
    gpg_err_set_errno (EIO);
  else
    fd_table[fd].reader = rd;

  UNLOCK (fd_table_lock);
  TRACE_SUC ("rd=%p (new)", rd);
  return rd;
}


int
_gpgme_io_read (int fd, void *buffer, size_t count)
{
  int nread;
  struct reader_context_s *ctx;
  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_read", fd,
	      "buffer=%p, count=%zd", buffer, count);

  ctx = find_reader (fd);
  if (!ctx)
    return TRACE_SYSRES (-1);
  if (ctx->eof_shortcut)
    return TRACE_SYSRES (0);

  LOCK (ctx->mutex);
  if (ctx->readpos == ctx->writepos && !ctx->error)
    {
      /* No data available.  */
      UNLOCK (ctx->mutex);
      TRACE_LOG  ("waiting for data from thread %p", ctx->thread_hd);
      wait_for_single_object (ctx->have_data_ev, INFINITE);
      TRACE_LOG  ("data from thread %p available", ctx->thread_hd);
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
	  TRACE_LOG  ("ResetEvent failed: ec=%d", (int) GetLastError ());
	  UNLOCK (ctx->mutex);
	  /* FIXME: Should translate the error code.  */
	  gpg_err_set_errno (EIO);
	  return TRACE_SYSRES (-1);
	}
    }
  if (!SetEvent (ctx->have_space_ev))
    {
      TRACE_LOG  ("SetEvent (%p) failed: ec=%d",
		  ctx->have_space_ev, (int) GetLastError ());
      UNLOCK (ctx->mutex);
      /* FIXME: Should translate the error code.  */
      gpg_err_set_errno (EIO);
      return TRACE_SYSRES (-1);
    }
  UNLOCK (ctx->mutex);

  TRACE_LOGBUFX (buffer, nread);
  return TRACE_SYSRES (nread);
}


/* The writer does use a simple buffering strategy so that we are
   informed about write errors as soon as possible (i.e. with the
   next call to the write function).  */
static DWORD CALLBACK
writer (void *arg)
{
  struct writer_context_s *ctx = arg;
  DWORD nwritten;
  int sock;
  TRACE_BEG  (DEBUG_SYSIO, "gpgme:writer", ctx->hdd,
	      "hd=%p, sock=%p, thread=%p, refcount=%d",
              ctx->hdd->hd, (void *)ctx->hdd->sock, ctx->thread_hd,
              ctx->refcount);

  if (ctx->hdd->hd != INVALID_HANDLE_VALUE)
    sock = 0;
  else
    sock = 1;

  for (;;)
    {
      LOCK (ctx->mutex);
      if (ctx->stop_me && !ctx->nbytes)
	{
	  UNLOCK (ctx->mutex);
	  break;
        }
      if (!ctx->nbytes)
	{
	  if (!SetEvent (ctx->is_empty))
	    TRACE_LOG  ("SetEvent failed: ec=%d", (int) GetLastError ());
	  if (!ResetEvent (ctx->have_data))
	    TRACE_LOG  ("ResetEvent failed: ec=%d", (int) GetLastError ());
	  UNLOCK (ctx->mutex);
	  TRACE_LOG ("idle");
	  wait_for_single_object (ctx->have_data, INFINITE);
	  TRACE_LOG ("got data to send");
	  LOCK (ctx->mutex);
       	}
      if (ctx->stop_me && !ctx->nbytes)
	{
	  UNLOCK (ctx->mutex);
	  break;
        }
      UNLOCK (ctx->mutex);

      TRACE_LOG  ("%s %zd bytes", sock?"sending":"writing", ctx->nbytes);

      /* Note that CTX->nbytes is not zero at this point, because
	 _gpgme_io_write always writes at least 1 byte before waking
	 us up, unless CTX->stop_me is true, which we catch above.  */
      if (sock)
        {
          /* We need to try send first because a socket handle can't
             be used with WriteFile.  */
          int n;

          n = send (ctx->hdd->sock, ctx->buffer, ctx->nbytes, 0);
          if (n < 0)
            {
              ctx->error_code = (int) WSAGetLastError ();
              ctx->error = 1;
              TRACE_LOG  ("send error: ec=%d", ctx->error_code);
              break;
            }
          nwritten = n;
        }
      else
        {
          if (!WriteFile (ctx->hdd->hd, ctx->buffer,
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
              TRACE_LOG  ("write error: ec=%d", ctx->error_code);
              break;
            }
        }
      TRACE_LOG  ("wrote %d bytes", (int) nwritten);

      LOCK (ctx->mutex);
      ctx->nbytes -= nwritten;
      UNLOCK (ctx->mutex);
    }
  /* Indicate that we have an error.  */
  if (!SetEvent (ctx->is_empty))
    TRACE_LOG  ("SetEvent failed: ec=%d", (int) GetLastError ());

  TRACE_LOG ("waiting for close");
  wait_for_single_object (ctx->close_ev, INFINITE);

  if (ctx->nbytes)
    TRACE_LOG  ("still %zd bytes in buffer at close time", ctx->nbytes);

  release_hddesc (ctx->hdd);
  close_handle (ctx->close_ev);
  close_handle (ctx->have_data);
  close_handle (ctx->is_empty);
  close_handle (ctx->thread_hd);
  DESTROY_LOCK (ctx->mutex);
  free (ctx);

  TRACE_SUC ("");
  return 0;
}


static struct writer_context_s *
create_writer (hddesc_t hdd)
{
  struct writer_context_s *ctx;
  SECURITY_ATTRIBUTES sec_attr;
  DWORD tid;


TRACE_BEG  (DEBUG_SYSIO, "gpgme:create_writer", hdd,
             "hd=%p sock=%p refcount=%d",
             hdd->hd, (void *)hdd->sock, hdd->refcount);

  memset (&sec_attr, 0, sizeof sec_attr);
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = FALSE;

  ctx = calloc (1, sizeof *ctx);
  if (!ctx)
    {
      TRACE_SYSERR (errno);
      return NULL;
    }

  ctx->hdd = ref_hddesc (hdd);

  ctx->refcount = 1;
  ctx->have_data = CreateEvent (&sec_attr, TRUE, FALSE, NULL);
  if (ctx->have_data)
    ctx->is_empty  = CreateEvent (&sec_attr, TRUE, TRUE, NULL);
  if (ctx->is_empty)
    ctx->close_ev = CreateEvent (&sec_attr, TRUE, FALSE, NULL);
  if (!ctx->have_data || !ctx->is_empty || !ctx->close_ev)
    {
      TRACE_LOG  ("CreateEvent failed: ec=%d", (int) GetLastError ());
      if (ctx->have_data)
	close_handle (ctx->have_data);
      if (ctx->is_empty)
	close_handle (ctx->is_empty);
      if (ctx->close_ev)
	close_handle (ctx->close_ev);
      release_hddesc (ctx->hdd);
      free (ctx);
      TRACE_SYSERR (EIO);
      return NULL;
    }

  INIT_LOCK (ctx->mutex);

  ctx->thread_hd = CreateThread (&sec_attr, 0, writer, ctx, 0, &tid );
  if (!ctx->thread_hd)
    {
      TRACE_LOG  ("CreateThread failed: ec=%d", (int) GetLastError ());
      DESTROY_LOCK (ctx->mutex);
      if (ctx->have_data)
	close_handle (ctx->have_data);
      if (ctx->is_empty)
	close_handle (ctx->is_empty);
      if (ctx->close_ev)
	close_handle (ctx->close_ev);
      release_hddesc (ctx->hdd);
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

  TRACE_SUC ("");
  return ctx;
}


static void
destroy_writer (struct writer_context_s *ctx)
{
  LOCK (ctx->mutex);
  ctx->refcount--;
  if (ctx->refcount != 0)
    {
      TRACE (DEBUG_SYSIO, "gpgme:destroy_writer", ctx,
              "hdd=%p refcount now %d", ctx->hdd, ctx->refcount);
      UNLOCK (ctx->mutex);
      return;
    }
  ctx->stop_me = 1;
  if (ctx->have_data)
    SetEvent (ctx->have_data);
  TRACE (DEBUG_SYSIO, "gpgme:destroy_writer", ctx,
          "hdd=%p close triggered", ctx->hdd);
  UNLOCK (ctx->mutex);

  /* Give the writer a chance to flush the buffer.  */
  wait_for_single_object (ctx->is_empty, INFINITE);

  /* After setting this event CTX is void.  */
  SetEvent (ctx->close_ev);
}


/* Find a writer context or create a new one.  Note that the writer
 * context will last until a _gpgme_io_close.  NULL is returned for a
 * bad FD or for other errors.  */
static struct writer_context_s *
find_writer (int fd)
{
  struct writer_context_s *wt = NULL;

  TRACE_BEG (DEBUG_SYSIO, "gpgme:find_writer", fd, "");

  LOCK (fd_table_lock);
  if (fd < 0 || fd >= fd_table_size || !fd_table[fd].used)
    {
      UNLOCK (fd_table_lock);
      gpg_err_set_errno (EBADF);
      TRACE_SUC ("EBADF");
      return NULL;
    }

  wt = fd_table[fd].writer;
  if (wt)
    {
      UNLOCK (fd_table_lock);
      TRACE_SUC ("wt=%p", wt);
      return wt;  /* Return already initialized writer thread object.  */
    }

  /* Create a new writer thread.  */
  TRACE_LOG  ("fd=%d -> hd=%p sock=%p dupfrom=%d creating writer",
              fd, fd_table[fd].hdd->hd, (void *)fd_table[fd].hdd->sock,
              fd_table[fd].dup_from);
  wt = create_writer (fd_table[fd].hdd);
  if (!wt)
    gpg_err_set_errno (EIO);
  else
    fd_table[fd].writer = wt;

  UNLOCK (fd_table_lock);
  TRACE_SUC ("wt=%p (new)", wt);
  return wt;
}


int
_gpgme_io_write (int fd, const void *buffer, size_t count)
{
  struct writer_context_s *ctx;
  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_write", fd,
	      "buffer=%p, count=%zd", buffer, count);
  TRACE_LOGBUFX (buffer, count);

  if (count == 0)
    return TRACE_SYSRES (0);

  ctx = find_writer (fd);
  if (!ctx)
    return TRACE_SYSRES (-1);

  LOCK (ctx->mutex);
  if (!ctx->error && ctx->nbytes)
    {
      /* Bytes are pending for send.  */

      /* Reset the is_empty event.  Better safe than sorry.  */
      if (!ResetEvent (ctx->is_empty))
	{
	  TRACE_LOG  ("ResetEvent failed: ec=%d", (int) GetLastError ());
	  UNLOCK (ctx->mutex);
	  /* FIXME: Should translate the error code.  */
	  gpg_err_set_errno (EIO);
	  return TRACE_SYSRES (-1);
	}
      UNLOCK (ctx->mutex);
      TRACE_LOG  ("waiting for empty buffer in thread %p", ctx->thread_hd);
      wait_for_single_object (ctx->is_empty, INFINITE);
      TRACE_LOG  ("thread %p buffer is empty", ctx->thread_hd);
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
   * used by the select() implementation to probe the channel.  */
  if (!ResetEvent (ctx->is_empty))
    {
      TRACE_LOG  ("ResetEvent failed: ec=%d", (int) GetLastError ());
      UNLOCK (ctx->mutex);
      /* FIXME: Should translate the error code.  */
      gpg_err_set_errno (EIO);
      return TRACE_SYSRES (-1);
    }
  if (!SetEvent (ctx->have_data))
    {
      TRACE_LOG  ("SetEvent failed: ec=%d", (int) GetLastError ());
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
  HANDLE rh;
  HANDLE wh;
  hddesc_t rhdesc;
  hddesc_t whdesc;
  SECURITY_ATTRIBUTES sec_attr;

  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_pipe", filedes,
	      "inherit_idx=%i (GPGME uses it for %s)",
	      inherit_idx, inherit_idx ? "reading" : "writing");

  /* Get a new empty file descriptor.  */
  rfd = new_fd ();
  if (rfd == -1)
    return TRACE_SYSRES (-1);
  wfd = new_fd ();
  if (wfd == -1)
    {
      release_fd (rfd);
      return TRACE_SYSRES (-1);
    }
  rhdesc = new_hddesc ();
  if (!rhdesc)
    {
      release_fd (rfd);
      release_fd (wfd);
      return TRACE_SYSRES (-1);
    }
  whdesc = new_hddesc ();
  if (!whdesc)
    {
      release_fd (rfd);
      release_fd (wfd);
      release_hddesc (rhdesc);
      return TRACE_SYSRES (-1);
    }

  /* Create a pipe.  */
  memset (&sec_attr, 0, sizeof (sec_attr));
  sec_attr.nLength = sizeof (sec_attr);
  sec_attr.bInheritHandle = TRUE;

  if (!CreatePipe (&rh, &wh, &sec_attr, PIPEBUF_SIZE))
    {
      TRACE_LOG  ("CreatePipe failed: ec=%d", (int) GetLastError ());
      release_fd (rfd);
      release_fd (wfd);
      release_hddesc (rhdesc);
      release_hddesc (whdesc);
      gpg_err_set_errno (EIO);
      return TRACE_SYSRES (-1);
    }

  /* Make one end inheritable.  */
  if (inherit_idx == 0)
    {
      if (!SetHandleInformation (wh, HANDLE_FLAG_INHERIT, 0))
        {
          gpg_err_set_errno (EIO);
          return TRACE_SYSRES (-1);
        }
    }
  else if (inherit_idx == 1)
    {
      if (!SetHandleInformation (rh, HANDLE_FLAG_INHERIT, 0))
        {
          gpg_err_set_errno (EIO);
          return TRACE_SYSRES (-1);
        }
    }

  /* Put the HANDLEs of the new pipe into the file descriptor table.
   * Note that we don't need to lock the table because we have just
   * acquired these two fresh fds and they are not known by any other
   * thread.  */
  fd_table[rfd].want_reader = 1;
  ref_hddesc (rhdesc)->hd = rh;
  fd_table[rfd].hdd = rhdesc;

  fd_table[wfd].want_writer = 1;
  ref_hddesc (whdesc)->hd = wh;
  fd_table[wfd].hdd = whdesc;

  filedes[0] = rfd;
  filedes[1] = wfd;
  TRACE_SUC ("read=0x%x (hdd=%p,hd=%p), write=0x%x (hdd=%p,hd=%p)",
             rfd, fd_table[rfd].hdd, fd_table[rfd].hdd->hd,
             wfd, fd_table[wfd].hdd, fd_table[wfd].hdd->hd);
  return 0;
}


/* Close out File descriptor FD.  */
int
_gpgme_io_close (int fd)
{
  _gpgme_close_notify_handler_t handler = NULL;
  void *value = NULL;

  TRACE_BEG (DEBUG_SYSIO, "_gpgme_io_close", fd, "");

  if (fd < 0)
    {
      gpg_err_set_errno (EBADF);
      return TRACE_SYSRES (-1);
    }

  LOCK (fd_table_lock);
  /* Check the size in the locked state because we may eventually add
   * code to change that size.  */
  if (fd >= fd_table_size || !fd_table[fd].used)
    {
      UNLOCK (fd_table_lock);
      gpg_err_set_errno (EBADF);
      return TRACE_SYSRES (-1);
    }

  TRACE_LOG  ("hdd=%p dupfrom=%d", fd_table[fd].hdd, fd_table[fd].dup_from);

  if (fd_table[fd].reader)
    {
      TRACE_LOG  ("destroying reader %p", fd_table[fd].reader);
      destroy_reader (fd_table[fd].reader);
      fd_table[fd].reader = NULL;
    }

  if (fd_table[fd].writer)
    {
      TRACE_LOG  ("destroying writer %p", fd_table[fd].writer);
      destroy_writer (fd_table[fd].writer);
      fd_table[fd].writer = NULL;
    }

  /* The handler may not use any fd function because the table is
   * locked.  Can we avoid this?  */
  handler = fd_table[fd].notify.handler;
  value   = fd_table[fd].notify.value;

  /* Release our reference to the handle descriptor.  Note that if no
   * reader or writer threads were used this release will also take
   * care that the handle descriptor is closed
   * (i.e. CloseHandle(hdd->hd) is called).  */
  release_hddesc (fd_table[fd].hdd);
  fd_table[fd].hdd = NULL;

  UNLOCK (fd_table_lock);

  /* Run the notification callback.  */
  if (handler)
    handler (fd, value);

  release_fd (fd);  /* FIXME: We should have a release_fd_locked () */

  return TRACE_SYSRES (0);
}


/* Set a close notification callback which is called right after FD
 * has been closed but before its slot (i.e. the FD number) is being
 * released.  The HANDLER may thus use the provided value of the FD
 * but it may not pass it to any I/O functions.  Note: Only the last
 * handler set for an FD is used.  */
int
_gpgme_io_set_close_notify (int fd, _gpgme_close_notify_handler_t handler,
			    void *value)
{
  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_set_close_notify", fd,
	      "close_handler=%p/%p", handler, value);

  LOCK (fd_table_lock);
  if (fd < 0 || fd >= fd_table_size || !fd_table[fd].used)
    {
      UNLOCK (fd_table_lock);
      gpg_err_set_errno (EBADF);
      return TRACE_SYSRES (-1);;
    }

  fd_table[fd].notify.handler = handler;
  fd_table[fd].notify.value = value;
  UNLOCK (fd_table_lock);
  return TRACE_SYSRES (0);
}


int
_gpgme_io_set_nonblocking (int fd)
{
  TRACE (DEBUG_SYSIO, "_gpgme_io_set_nonblocking", fd, "");
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

#if !defined(GPGRT_PROCESS_STDIO_NUL) /* libgpg-error is old.  */
int
_gpgme_io_spawn_sans_helper (const char *path, char *const spawn_argv[],
                             unsigned int spawn_flags,
                             struct spawn_fd_item_s *fd_list,
                             void (*atfork) (void *opaque, int reserved),
                             void *atforkvalue, assuan_pid_t *r_pid)
{
  static int spawn_warning_shown;

  if (1)
    {
      /* This is a common mistake for new users of gpgme not to include
         gpgme-w32spawn.exe with their binary. So we want to make
         this transparent to developers. If users have somehow messed
         up their installation this should also be properly communicated
         as otherwise calls to gnupg will result in unsupported protocol
         errors that do not explain a lot. */
      if (!spawn_warning_shown)
        {
          char *msg;
          gpgrt_asprintf (&msg, "gpgme-w32spawn.exe was not found in the "
                                "detected installation directory of GpgME"
                                "\n\t\"%s\"\n\n"
                                "Crypto operations will not work.\n\n"
                                "If you see this it indicates a problem "
                                "with your installation.\n"
                                "Please report the problem to your "
                                "distributor of GpgME.\n\n"
                                "Developer's Note: The install dir can be "
                                "manually set with: gpgme_set_global_flag",
                                _gpgme_get_inst_dir ());
          MessageBoxA (NULL, msg, "GpgME not installed correctly", MB_OK);
          gpgrt_free (msg);
          spawn_warning_shown = 1;
        }
      gpg_err_set_errno (EIO);
      return TRACE_SYSRES (-1);
    }
}
#else
/* Format string to represent the handle.  */
#ifdef _WIN64
#define FMT_HD "%llu"
#else
#define FMT_HD "%u"
#endif

/* Enough string space to put the handle with FMT_HD in 64-bit.  */
#define MAX_ARG_STR 23

int
_gpgme_io_spawn_sans_helper (const char *path, char *const spawn_argv[],
                             unsigned int spawn_flags,
                             struct spawn_fd_item_s *fd_list,
                             void (*atfork) (void *opaque, int reserved),
                             void *atforkvalue, assuan_pid_t *r_pid)
{
  int i;
  gpg_err_code_t ec;
  unsigned int flags = GPGRT_PROCESS_STDIO_NUL;
  gpgrt_spawn_actions_t act;
  gpgrt_process_t process;
  HANDLE handle_in, handle_out, handle_err;
  const char **argv;
  int argc;
  char *p;
  HANDLE hProcess;
  HANDLE handles[32];
  int inherit_hd = 0;

  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_spawn", path,
	      "path=%s", path);

  (void)atfork;
  (void)atforkvalue;

  i = 0;
  while (spawn_argv[i])
    {
      TRACE_LOG  ("argv[%2i] = %s", i, spawn_argv[i]);
      i++;
    }
  argc = i;

  argv = malloc ((sizeof (char *) + MAX_ARG_STR)* (argc + 1));
  if (!argv)
    return TRACE_SYSRES (-1);
  p = (char *)&argv[argc+1];

  for (i = 0; i < argc; i++)
    argv[i] = spawn_argv[i];
  argv[argc] = NULL;

  flags |= GPGRT_PROCESS_DETACHED;
  if ((spawn_flags & IOSPAWN_FLAG_ALLOW_SET_FG))
    flags |= GPGRT_PROCESS_ALLOW_SET_FG;

  LOCK (fd_table_lock);
  for (i = 0; fd_list[i].fd != -1; i++)
    {
      int fd = fd_list[i].fd;
      HANDLE hd = INVALID_HANDLE_VALUE;

      if (fd >= 0 && fd < fd_table_size && fd_table[fd].used
          && fd_table[fd].hdd)
	hd = fd_table[fd].hdd->hd;

      fd_list[i].peer_name = hd;
    }
  UNLOCK (fd_table_lock);

  handle_in = handle_out = handle_err = INVALID_HANDLE_VALUE;

  for (i = 0; fd_list[i].fd != -1; i++)
    {
      HANDLE hd = fd_list[i].peer_name;
      int idx;
      int r;
      int std_hd = 0;

      if (fd_list[i].dup_to == 0)
        {
          handle_in = hd;
          std_hd++;
        }
      else if (fd_list[i].dup_to == 1)
        {
          handle_out = hd;
          std_hd++;
        }
      else if (fd_list[i].dup_to == 2)
        {
          handle_err = hd;
          std_hd++;
        }

      idx = fd_list[i].arg_loc;
      if (idx == 0)
        continue;
      if (idx >= argc)
        /* something goes wrong, ignore.  */
        continue;

      if (!std_hd)
        {
          if (inherit_hd < DIM (handles) - 1)
            {
              if (hd != INVALID_HANDLE_VALUE)
                handles[inherit_hd++] = hd;
            }
          else
            {
              free (argv);
              return TRACE_SYSRES (-1);
            }
        }

      /* Fix the arg at ARG_LOC.  */
      if (spawn_argv[idx][0] == '-' && spawn_argv[idx][1] == '&')
        r = snprintf (p, MAX_ARG_STR, "-&" FMT_HD, (uintptr_t)hd);
      else
        r = snprintf (p, MAX_ARG_STR, FMT_HD, (uintptr_t)hd);
      argv[idx] = p;

      if (r < 0)
        {
          free (argv);
          return TRACE_SYSRES (-1);
        }

      p += r + 1;
    }

  handles[inherit_hd] = INVALID_HANDLE_VALUE;

  ec = gpgrt_spawn_actions_new (&act);
  if (ec)
    {
      free (argv);
      return TRACE_SYSRES (-1);
    }

  gpgrt_spawn_actions_set_redirect (act, handle_in, handle_out, handle_err);
  gpgrt_spawn_actions_set_inherit_handles (act, handles);

  ec = gpgrt_process_spawn (path, argv+1, flags, act, &process);
  gpgrt_spawn_actions_release (act);
  free (argv);
  if (ec)
    {
      gpg_err_set_errno (EIO);
      return TRACE_SYSRES (-1);
    }

  gpgrt_process_ctl (process, GPGRT_PROCESS_GET_P_HANDLE, &hProcess);

  TRACE_LOG  ("process=%p", hProcess);

#if ASSUAN_VERSION_NUMBER < 0x030000
  if (r_pid)
    gpgrt_process_ctl (process, GPGRT_PROCESS_GET_PROC_ID, r_pid);

  /* We don't need to wait for the process.  */
  close_handle (hProcess);
#else
  if (r_pid)
    *r_pid = (assuan_pid_t)hProcess;
  else
    /* We don't need to wait for the process.  */
    close_handle (hProcess);
#endif

  if (!(spawn_flags & IOSPAWN_FLAG_NOCLOSE))
    {
      for (i = 0; fd_list[i].fd != -1; i++)
	_gpgme_io_close (fd_list[i].fd);
    }

  for (i = 0; fd_list[i].fd != -1; i++)
    if (fd_list[i].dup_to == -1)
      TRACE_LOG  ("fd[%i] = 0x%x -> %p", i, fd_list[i].fd,
		  fd_list[i].peer_name);
    else
      TRACE_LOG  ("fd[%i] = 0x%x -> %p (std%s)", i, fd_list[i].fd,
		  fd_list[i].peer_name, (fd_list[i].dup_to == 0) ? "in" :
		  ((fd_list[i].dup_to == 1) ? "out" : "err"));

  gpgrt_process_release (process);

  return TRACE_SYSRES (0);
}
#endif


int
_gpgme_io_spawn (const char *path, char *const argv[], unsigned int flags,
		 struct spawn_fd_item_s *fd_list,
		 void (*atfork) (void *opaque, int reserved),
		 void *atforkvalue, assuan_pid_t *r_pid)
{
  PROCESS_INFORMATION pi =
    {
      NULL,      /* returns process handle */
      0,         /* returns primary thread handle */
      0,         /* returns pid */
      0          /* returns tid */
    };
  int i;

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

  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_spawn", path,
	      "path=%s", path);

  spawnhelper = _gpgme_get_w32spawn_path ();
  if (!spawnhelper)
    return _gpgme_io_spawn_sans_helper (path, argv, flags,
                                        fd_list, atfork, atforkvalue, r_pid);

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
  args[0] = (char *)spawnhelper;
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
      free (tmp_name);
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
  if (!_gpgme_create_process_utf8 (spawnhelper,
                                   arg_string,
                                   &sec_attr, /* process security attributes */
                                   &sec_attr, /* thread security attributes */
                                   FALSE,     /* inherit handles */
                                   cr_flags,  /* creation flags */
                                   NULL,      /* environment */
                                   NULL,      /* use current drive/directory */
                                   &si,       /* startup information */
                                   &pi))      /* returns process information */
    {
      int lasterr = (int)GetLastError ();
      TRACE_LOG  ("CreateProcess failed: ec=%d", lasterr);
      free (arg_string);
      close (tmp_fd);
      DeleteFileA (tmp_name);
      free (tmp_name);

      /* FIXME: Should translate the error code.  */
      gpg_err_set_errno (EIO);
      return TRACE_SYSRES (-1);
    }

  if (flags & IOSPAWN_FLAG_ALLOW_SET_FG)
    _gpgme_allow_set_foreground_window ((pid_t)pi.dwProcessId);

  /* Insert the inherited handles.  */
  LOCK (fd_table_lock);
  for (i = 0; fd_list[i].fd != -1; i++)
    {
      int fd = fd_list[i].fd;
      HANDLE ohd = INVALID_HANDLE_VALUE;
      HANDLE hd = INVALID_HANDLE_VALUE;

      /* Make it inheritable for the wrapper process.  */
      if (fd >= 0 && fd < fd_table_size && fd_table[fd].used
          && fd_table[fd].hdd)
	ohd = fd_table[fd].hdd->hd;

      if (!DuplicateHandle (GetCurrentProcess(), ohd,
			    pi.hProcess, &hd, 0, TRUE, DUPLICATE_SAME_ACCESS))
	{
	  TRACE_LOG  ("DuplicateHandle failed: ec=%d", (int) GetLastError ());
	  TerminateProcess (pi.hProcess, 0);
	  /* Just in case TerminateProcess didn't work, let the
	     process fail on its own.  */
	  ResumeThread (pi.hThread);
	  close_handle (pi.hThread);
	  close_handle (pi.hProcess);

	  close (tmp_fd);
	  DeleteFileA (tmp_name);
          free (tmp_name);

	  /* FIXME: Should translate the error code.  */
	  gpg_err_set_errno (EIO);
          UNLOCK (fd_table_lock);
	  return TRACE_SYSRES (-1);
        }
      /* Return the child name of this handle.  */
      fd_list[i].peer_name = hd;
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

    if (flags)
      snprintf (line, BUFFER_MAX, "~%i \n", flags);
    else
      strcpy (line, "\n");
    for (i = 0; fd_list[i].fd != -1; i++)
      {
	/* Strip the newline.  */
	len = strlen (line) - 1;

	/* Format is: Local name, stdin/stdout/stderr, peer name, argv idx.  */
	snprintf (&line[len], BUFFER_MAX - len, "0x%x %d %p %d  \n",
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

  free (tmp_name);
  free (arg_string);

  UNLOCK (fd_table_lock);

  TRACE_LOG  ("CreateProcess ready: hProcess=%p, hThread=%p, "
	      "dwProcessID=%d, dwThreadId=%d",
	      pi.hProcess, pi.hThread,
	      (int) pi.dwProcessId, (int) pi.dwThreadId);

  if (ResumeThread (pi.hThread) == (DWORD)(-1))
    TRACE_LOG  ("ResumeThread failed: ec=%d", (int) GetLastError ());

  close_handle (pi.hThread);

  TRACE_LOG  ("process=%p", pi.hProcess);

#if ASSUAN_VERSION_NUMBER < 0x030000
  if (r_pid)
    *r_pid = (pid_t)pi.dwProcessId;

  /* We don't need to wait for the process.  */
  close_handle (pi.hProcess);
#else
  if (r_pid)
    *r_pid = (assuan_pid_t)pi.hProcess;
  else
    /* We don't need to wait for the process.  */
    close_handle (pi.hProcess);
#endif

  if (! (flags & IOSPAWN_FLAG_NOCLOSE))
    {
      for (i = 0; fd_list[i].fd != -1; i++)
	_gpgme_io_close (fd_list[i].fd);
    }

  for (i = 0; fd_list[i].fd != -1; i++)
    if (fd_list[i].dup_to == -1)
      TRACE_LOG  ("fd[%i] = 0x%x -> %p", i, fd_list[i].fd,
		  fd_list[i].peer_name);
    else
      TRACE_LOG  ("fd[%i] = 0x%x -> %p (std%s)", i, fd_list[i].fd,
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
  void *dbg_help = NULL;
  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_select", fds,
	      "nfds=%zd, nonblock=%u", nfds, nonblock);

#if 0
 restart:
#endif
  TRACE_SEQ (dbg_help, "selecting [ ");
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
              /* FIXME: A find_reader_locked() along with separate
               * lock calls might be a better appaoched here.  */
	      struct reader_context_s *ctx = find_reader (fds[i].fd);

	      if (!ctx)
		TRACE_LOG  ("error: no reader for FD 0x%x (ignored)",
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
	      struct writer_context_s *ctx = find_writer (fds[i].fd);

	      if (!ctx)
		TRACE_LOG  ("error: no writer for FD 0x%x (ignored)",
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
  if (code < WAIT_OBJECT_0 + nwait)
    {
      /* The WFMO is a really silly function: It does return either
	 the index of the signaled object or if 2 objects have been
	 signalled at the same time, the index of the object with the
	 lowest object is returned - so and how do we find out how
	 many objects have been signaled?.  The only solution I can
	 imagine is to test each object starting with the returned
	 index individually - how dull.  */
      any = 0;
      for (i = code - WAIT_OBJECT_0; i < nwait; i++)
	{
	  if (wait_for_single_object (waitbuf[i], 0) == WAIT_OBJECT_0)
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

	  TRACE_LOG  ("WFMO invalid handle %d removed", j);
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
      TRACE_LOG  ("WFMO failed: %d", le);
      count = -1;
    }
  else
    {
      TRACE_LOG  ("WFMO returned %d", code);
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


/* Write the printable version of FD to BUFFER which has an allocated
 * length of BUFLEN.  The printable version is the representation on
 * the command line that the child process expects.  Note that this
 * works closely together with the gpgme-32spawn wrapper process which
 * translates these command line args to the real handles. */
int
_gpgme_io_fd2str (char *buffer, int buflen, int fd)
{
  return snprintf (buffer, buflen, "%d", fd);
}


int
_gpgme_io_dup (int fd)
{
  int newfd;
  struct reader_context_s *rd_ctx;
  struct writer_context_s *wt_ctx;
  int want_reader, want_writer;

  TRACE_BEG (DEBUG_SYSIO, "_gpgme_io_dup", fd, "");

  LOCK (fd_table_lock);
  if (fd < 0 || fd >= fd_table_size || !fd_table[fd].used)
    {
      UNLOCK (fd_table_lock);
      gpg_err_set_errno (EBADF);
      return TRACE_SYSRES (-1);
    }

  newfd = new_fd();
  if (newfd == -1)
    {
      UNLOCK (fd_table_lock);
      gpg_err_set_errno (EMFILE);
      return TRACE_SYSRES (-1);
    }

  fd_table[newfd].hdd = ref_hddesc (fd_table[fd].hdd);
  fd_table[newfd].dup_from = fd;
  want_reader = fd_table[fd].want_reader;
  want_writer = fd_table[fd].want_writer;

  UNLOCK (fd_table_lock);

  rd_ctx = want_reader? find_reader (fd) : NULL;
  if (rd_ctx)
    {
      /* NEWFD initializes a freshly allocated slot and does not need
       * to be locked.  */
      LOCK (rd_ctx->mutex);
      rd_ctx->refcount++;
      UNLOCK (rd_ctx->mutex);
      fd_table[newfd].reader = rd_ctx;
    }

  wt_ctx = want_writer? find_writer (fd) : NULL;
  if (wt_ctx)
    {
      LOCK (wt_ctx->mutex);
      wt_ctx->refcount++;
      UNLOCK (wt_ctx->mutex);
      fd_table[newfd].writer = wt_ctx;
    }

  return TRACE_SYSRES (newfd);
}


/* The following interface is only useful for GPGME Glib and Qt.  */

/* Compatibility interface, obsolete.  */
void *
gpgme_get_giochannel (int fd)
{
  (void)fd;
  return NULL;
}


/* Look up the giochannel or qiodevice for file descriptor FD.  */
void *
gpgme_get_fdptr (int fd)
{
  (void)fd;
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
  hddesc_t hdd;

  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_socket", domain,
	      "type=%i, protp=%i", type, proto);

  fd = new_fd();
  if (fd == -1)
    return TRACE_SYSRES (-1);
  hdd = new_hddesc ();
  if (!hdd)
    {
      UNLOCK (fd_table_lock);
      release_fd (fd);
      gpg_err_set_errno (ENOMEM);
      return TRACE_SYSRES (-1);
    }

  res = socket (domain, type, proto);
  if (res == INVALID_SOCKET)
    {
      release_fd (fd);
      gpg_err_set_errno (wsa2errno (WSAGetLastError ()));
      return TRACE_SYSRES (-1);
    }
  ref_hddesc (hdd)->sock = res;
  fd_table[fd].hdd = hdd;
  fd_table[fd].want_reader = 1;
  fd_table[fd].want_writer = 1;

  TRACE_SUC ("hdd=%p, fd=%d, sock=%p", hdd, fd, (void *)hdd->sock);

  return fd;
}


int
_gpgme_io_connect (int fd, struct sockaddr *addr, int addrlen)
{
  int res;
  int sock;

  TRACE_BEG  (DEBUG_SYSIO, "_gpgme_io_connect", fd,
	      "addr=%p, addrlen=%i", addr, addrlen);

  LOCK (fd_table_lock);
  if (fd < 0 || fd >= fd_table_size || !fd_table[fd].used || !fd_table[fd].hdd)
    {
      gpg_err_set_errno (EBADF);
      UNLOCK (fd_table_lock);
      return TRACE_SYSRES (-1);
    }
  sock = fd_table[fd].hdd->sock;
  UNLOCK (fd_table_lock);

  res = connect (sock, addr, addrlen);
  if (res)
    {
      gpg_err_set_errno (wsa2errno (WSAGetLastError ()));
      return TRACE_SYSRES (-1);
    }

  TRACE_SUC ("");
  return 0;
}
