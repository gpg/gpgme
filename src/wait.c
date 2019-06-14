/* wait.c
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2007 g10 Code GmbH
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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include "util.h"
#include "context.h"
#include "ops.h"
#include "wait.h"
#include "sema.h"
#include "priv-io.h"
#include "engine.h"
#include "debug.h"
#include "fdtable.h"


/* Wrapper for the user wait handler to match the exported prototype.
 * This is used by _gpgme_add_io_cb_user.  */
static gpg_error_t
user_io_cb_handler (void *data, int fd)
{
  struct io_cb_tag_s *tag = data;
  gpg_error_t err;
  uint64_t serial;
  gpgme_ctx_t ctx;
  gpg_error_t op_err;
  struct io_select_s iosel;

  (void)fd;

  assert (data);
  serial = tag->serial;
  assert (serial);

  iosel.fd = fd;
  iosel.for_read = 0;  /* we don't care.  */
  iosel.for_write = 0; /* we don't care.  */
  iosel.signaled = 1;  /* we are only called when I/O is pending.  */
  _gpgme_fdtable_set_signaled (&iosel, 1);

  err = _gpgme_fdtable_run_io_cbs (serial, &op_err, NULL);
  if (err || op_err)
    ;
  else if (!_gpgme_fdtable_get_count (serial, 0))
    {
      /* No more active callbacks - emit a DONE.  */
      struct gpgme_io_event_done_data done_data =  { 0, 0 };
      _gpgme_get_ctx (serial, &ctx);
      if (ctx)
        _gpgme_engine_io_event (ctx->engine, GPGME_EVENT_DONE, &done_data);
    }
  return 0;
}



/* Register the file descriptor FD with the handler FNC (which gets
   FNC_DATA as its first argument) for the direction DIR.  DATA should
   be the context for which the fd is added.  R_TAG will hold the tag
   that can be used to remove the fd.  This function is used for the
   global and the private wait loops. */
gpgme_error_t
_gpgme_add_io_cb (void *data, int fd, int dir, gpgme_io_cb_t fnc,
		  void *fnc_data, void **r_tag)
{
  gpgme_error_t err;
  gpgme_ctx_t ctx = (gpgme_ctx_t) data;
  struct io_cb_tag_s *tag;

  TRACE_BEG  (DEBUG_SYSIO, __func__, NULL, "ctx=%lu fd=%d, dir %d",
              CTXSERIAL (ctx), fd, dir);

  if (!fnc)
    return gpg_error (GPG_ERR_INV_ARG);

  assert (fnc);
  assert (ctx);

  tag = calloc (1, sizeof *tag);
  if (!tag)
    return gpg_error_from_syserror ();
  tag->serial = ctx->serial;
  tag->fd = fd;

  err = _gpgme_fdtable_set_io_cb (fd, ctx->serial, dir, fnc, fnc_data);
  if (err)
    {
      free (tag);
      return TRACE_ERR (err);
    }

  *r_tag = tag;

  TRACE_SUC ("tag=%p", tag);
  return 0;
}


/* Register the file descriptor FD with the handler FNC (which gets
   FNC_DATA as its first argument) for the direction DIR.  DATA should
   be the context for which the fd is added.  R_TAG will hold the tag
   that can be used to remove the fd.  This function is used for the
   user wait loops. */
gpg_error_t
_gpgme_add_io_cb_user (void *data, int fd, int dir, gpgme_io_cb_t fnc,
                       void *fnc_data, void **r_tag)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) data;
  struct io_cb_tag_s *tag;
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_SYSIO, __func__, NULL, "ctx=%lu fd=%d, dir %d",
              CTXSERIAL (ctx), fd, dir);

  assert (ctx);
  err = _gpgme_add_io_cb (data, fd, dir, fnc, fnc_data, r_tag);
  if (err)
    return TRACE_ERR (err);
  tag = *r_tag;
  assert (tag);

  err = ctx->user_io_cbs.add (ctx->user_io_cbs.add_priv, fd, dir,
                              user_io_cb_handler, *r_tag,
                              &tag->user_tag);
  if (err)
    _gpgme_remove_io_cb (*r_tag);
  return TRACE_ERR (err);
}


/*  This function is used for the global and the private wait loops. */
void
_gpgme_remove_io_cb (void *data)
{
  struct io_cb_tag_s *tag = data;
  gpg_error_t err;

  assert (tag);

  err = _gpgme_fdtable_set_io_cb (tag->fd, tag->serial, 0, NULL, NULL);
  if (err)
    {
      TRACE (DEBUG_CTX, __func__, NULL, "tag=%p (ctx=%lu fd=%d) failed: %s",
             tag, tag->serial, tag->fd, gpg_strerror (err));
    }
  else
    {
      TRACE (DEBUG_CTX, __func__, NULL, "tag=%p (ctx=%lu fd=%d) done",
             tag, tag->serial, tag->fd);
    }
  free (tag);
}


/* This function is used for the user wait loops. */
void
_gpgme_remove_io_cb_user (void *data)
{
  struct io_cb_tag_s *tag = data;
  gpgme_ctx_t ctx;

  assert (tag);
  _gpgme_get_ctx (tag->serial, &ctx);

  if (ctx)
    ctx->user_io_cbs.remove (tag->user_tag);
  _gpgme_remove_io_cb (data);
}



/* The internal I/O callback function used for the global event loop.
   That loop is used for all asynchronous operations (except key
   listing) for which no user I/O callbacks are specified.

   A context sets up its initial I/O callbacks and then sends the
   GPGME_EVENT_START event.  After that, it is added to the global
   list of active contexts.

   The gpgme_wait function contains a select() loop over all file
   descriptors in all active contexts.  If an error occurs, it closes
   all fds in that context and moves the context to the global done
   list.  Likewise, if a context has removed all I/O callbacks, it is
   moved to the global done list.

   All contexts in the global done list are eligible for being
   returned by gpgme_wait if requested by the caller.  */
void
_gpgme_wait_global_event_cb (void *data, gpgme_event_io_t type,
			     void *type_data)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) data;
  gpg_error_t err;

  assert (ctx);

  switch (type)
    {
    case GPGME_EVENT_START:
      {
        err = _gpgme_fdtable_set_active (ctx->serial);
	if (err)
	  /* An error occurred.  Close all fds in this context, and
	     send the error in a done event.  */
	  _gpgme_cancel_with_err (ctx->serial, err, 0);
      }
      break;

    case GPGME_EVENT_DONE:
      {
	gpgme_io_event_done_data_t done_data =
	  (gpgme_io_event_done_data_t) type_data;

        _gpgme_fdtable_set_done (ctx->serial,
                                 done_data->err, done_data->op_err);
      }
      break;

    case GPGME_EVENT_NEXT_KEY:
      assert (!"Unexpected event GPGME_EVENT_NEXT_KEY");
      break;

    case GPGME_EVENT_NEXT_TRUSTITEM:
      assert (!"Unexpected event GPGME_EVENT_NEXT_TRUSTITEM");
      break;

    default:
      assert (!"Unexpected event");
      break;
    }
}


/* The internal I/O callback function used for private event loops.
 * The private event loops are used for all blocking operations, and
 * for the key and trust item listing operations.  They are completely
 * separated from each other.  */
void
_gpgme_wait_private_event_cb (void *data, gpgme_event_io_t type,
			      void *type_data)
{
  switch (type)
    {
    case GPGME_EVENT_START:
      /* Nothing to do here, as the wait routine is called after the
	 initialization is finished.  */
      break;

    case GPGME_EVENT_DONE:
      break;

    case GPGME_EVENT_NEXT_KEY:
      _gpgme_op_keylist_event_cb (data, type, type_data);
      break;

    case GPGME_EVENT_NEXT_TRUSTITEM:
      _gpgme_op_trustlist_event_cb (data, type, type_data);
      break;
    }
}


/* The internal I/O callback function used for user event loops.  User
 * event loops are used for all asynchronous operations for which a
 * user callback is defined.  */
void
_gpgme_wait_user_event_cb (void *data, gpgme_event_io_t type, void *type_data)
{
  gpgme_ctx_t ctx = data;

  if (ctx->user_io_cbs.event)
    ctx->user_io_cbs.event (ctx->user_io_cbs.event_priv, type, type_data);
}



/* Perform asynchronous operations in the global event loop (ie, any
   asynchronous operation except key listing and trustitem listing
   operations).  If CTX is not a null pointer, the function will
   return if the asynchronous operation in the context CTX finished.
   Otherwise the function will return if any asynchronous operation
   finished.  If HANG is zero, the function will not block for a long
   time.  Otherwise the function does not return until an operation
   matching CTX finished.

   If a matching context finished, it is returned, and *STATUS is set
   to the error value of the operation in that context.  Otherwise, if
   the timeout expires, NULL is returned and *STATUS is 0.  If an
   error occurs, NULL is returned and *STATUS is set to the error
   value.  */
gpgme_ctx_t
gpgme_wait_ext (gpgme_ctx_t ctx, gpgme_error_t *status,
		gpgme_error_t *op_err, int hang)
{
  gpg_error_t err;
  io_select_t fds = NULL;
  unsigned int nfds;
  int nr;
  uint64_t serial;

  TRACE_BEG  (DEBUG_SYSIO, __func__, NULL, "ctx=%lu hang=%d",
              CTXSERIAL (ctx), hang);

  do
    {
      /* Get all fds of CTX (or all if CTX is NULL) we want to wait
       * for and which are in the active state.  */
      TRACE_LOG
        ("active=%u done=%u !done=%d cbs=%u",
         _gpgme_fdtable_get_count (ctx?ctx->serial:0,FDTABLE_FLAG_ACTIVE),
         _gpgme_fdtable_get_count (ctx?ctx->serial:0,FDTABLE_FLAG_DONE),
         _gpgme_fdtable_get_count (ctx?ctx->serial:0,FDTABLE_FLAG_NOT_DONE),
         _gpgme_fdtable_get_count (ctx?ctx->serial:0,0));

      free (fds);
      nfds = _gpgme_fdtable_get_fds (&fds, ctx? ctx->serial : 0,
                                     ( FDTABLE_FLAG_ACTIVE
                                       | FDTABLE_FLAG_CLEAR));
      if (!nfds)
        {
          err = gpg_error_from_syserror ();
          if (gpg_err_code (err) != GPG_ERR_MISSING_ERRNO)
            {
              if (status)
                *status = err;
              if (op_err)
                *op_err = 0;
              ctx = NULL;
              goto leave;
            }
          /* Nothing to select.  */

          if (!_gpgme_fdtable_get_count (ctx? ctx->serial : 0,
                                         FDTABLE_FLAG_NOT_DONE))
            {
              if (status)
                *status = 0;
              if (op_err)
                *op_err = 0;
              goto leave;
            }
          /* There are not yet active FDS.  Use the select's standard
           * timeout and then try again.  */
        }

      nr = _gpgme_io_select (fds, nfds, 0);
      if (nr < 0)
        {
          if (status)
            *status = gpg_error_from_syserror ();
          if (op_err)
            *op_err = 0;
          ctx = NULL;
          goto leave;
        }
      _gpgme_fdtable_set_signaled (fds, nfds);

      err = _gpgme_fdtable_run_io_cbs (ctx? ctx->serial : 0, op_err, &serial);
      if (err || (op_err && *op_err))
        {
          if (status)
            *status = err;
          if (serial)
            _gpgme_get_ctx (serial, &ctx);
          hang = 0;
        }
      else
        {
          serial = _gpgme_fdtable_get_done (ctx? ctx->serial : 0, status,
                                            op_err);
          if (serial)
            {
              _gpgme_get_ctx (serial, &ctx);
              hang = 0;
            }
          else if (!hang)
            {
              ctx = NULL;
              if (status)
                *status = 0;
              if (op_err)
                *op_err = 0;
            }
        }
    }
  while (hang);

 leave:
  free (fds);
  if (status)
    TRACE_LOG ("status=%d", *status);
  if (op_err)
    TRACE_LOG ("op_err=%d", *op_err);
  TRACE_SUC ("result=%lu", ctx? ctx->serial : 0);
  return ctx;
}


gpgme_ctx_t
gpgme_wait (gpgme_ctx_t ctx, gpgme_error_t *status, int hang)
{
  return gpgme_wait_ext (ctx, status, NULL, hang);
}



/* Wait until the blocking operation in context CTX has finished and
 * return the error value.  If COND is not NULL return early if COND
 * is satisfied.  A session based error will be returned at R_OP_ERR
 * if it is not NULL.  */
gpgme_error_t
_gpgme_sync_wait (gpgme_ctx_t ctx, volatile int *cond, gpg_error_t *r_op_err)
{
  gpgme_error_t err = 0;
  int hang = 1;
  io_select_t fds = NULL;
  unsigned int nfds;
  int nr;

  TRACE_BEG  (DEBUG_SYSIO, __func__, NULL, "ctx=%lu", CTXSERIAL (ctx));

  if (r_op_err)
    *r_op_err = 0;

  if (!ctx)
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }

  do
    {
      /* Get all fds of CTX we want to wait for.  */
      free (fds);
      nfds = _gpgme_fdtable_get_fds (&fds, ctx->serial,
                                     FDTABLE_FLAG_CLEAR);
      if (!nfds)
        {
          err = gpg_error_from_syserror ();
          if (gpg_err_code (err) != GPG_ERR_MISSING_ERRNO)
            goto leave;
        }
      else
        {
          nr = _gpgme_io_select (fds, nfds, 0);
          if (nr < 0)
            {
              /* An error occurred.  Close all fds in this context, and
                 signal it.  */
              err = gpg_error_from_syserror ();
              _gpgme_cancel_with_err (ctx->serial, err, 0);
              goto leave;
            }
          _gpgme_fdtable_set_signaled (fds, nfds);

          err = _gpgme_fdtable_run_io_cbs (ctx->serial, r_op_err, NULL);
          if (err || (r_op_err && *r_op_err))
            goto leave;
        }

      if (!_gpgme_fdtable_get_count (ctx->serial, 0))
	{
          /* No more matching fds with IO callbacks.  */
	  struct gpgme_io_event_done_data data = {0, 0};
	  _gpgme_engine_io_event (ctx->engine, GPGME_EVENT_DONE, &data);
	  hang = 0;
	}
      if (cond && *cond)
	hang = 0;
    }
  while (hang);
  err = 0;

 leave:
  free (fds);
  return TRACE_ERR (err);
}
