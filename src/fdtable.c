/* fdtable.c - Keep track of file descriptors.
 * Copyright (C) 2019 g10 Code GmbH
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
#include <assert.h>

#include "gpgme.h"
#include "debug.h"
#include "context.h"
#include "fdtable.h"


/* The table to hold information about file descriptors.  Currently we
 * use a linear search and extend the table as needed.  Eventually we
 * may swicth to a hash table and allocate items on the fly. */
struct fdtable_item_s
{
  int fd;  /* -1 indicates an unused entry.  */

  uint64_t owner;  /* The S/N of the context owning this FD.  */

  /* ACTIVE is set if this fd is in the global event loop, has an
   * active callback (.io_cb), and has seen the start event. */
  unsigned int active:1;
  /* DONE is set if this fd was previously active but is not active
   * any longer, either because is finished successfully or its I/O
   * callback returned an error.  Note that ACTIVE and DONE should
   * never both be set. */
  unsigned int done:1;

  /* Infos for io_select.  */
  unsigned int for_read:1;
  unsigned int for_write:1;
  unsigned int signaled:1;

  /* We are in a closing handler.  Note that while this flag is active
   * the remove code holds an index into the table.  Thus we better
   * make sure that the index won't change.  Or change the removal
   * code to re-find the fd.  */
  unsigned int closing:1;

  /* We are currently running the IO callback. */
  unsigned int io_cb_running:1;

  /* The I/O callback handler with its value context. */
  struct {
    gpgme_io_cb_t cb;
    void *value;
  } io_cb;

  /* The error code and the operational error for the done status.  */
  gpg_error_t done_status;
  gpg_error_t done_op_err;

  /* The callback to be called before the descriptor is actually closed.  */
  struct {
    fdtable_handler_t handler;
    void *value;
  } close_notify;
};
typedef struct fdtable_item_s *fdtable_item_t;

/* The actual table, its size and the lock to guard access.  */
static fdtable_item_t fdtable;
static unsigned int   fdtablesize;
DEFINE_STATIC_LOCK (fdtable_lock);



/* Insert FD into our file descriptor table.  This function checks
 * that FD is not yet in the table.  On success 0 is returned; if FD
 * is already in the table GPG_ERR_DUP_KEY is returned.  Other error
 * codes may also be returned. */
gpg_error_t
_gpgme_fdtable_insert (int fd)
{
  gpg_error_t err;
  int firstunused, idx;

  TRACE_BEG  (DEBUG_SYSIO, __func__, NULL, "fd=%d", fd);

  if (fd < 0 )
    return TRACE_ERR (gpg_error (GPG_ERR_INV_ARG));

  LOCK (fdtable_lock);

  firstunused = -1;
  for (idx=0; idx < fdtablesize; idx++)
    if (fdtable[idx].fd == -1)
      {
        if (firstunused == -1)
          firstunused = idx;
      }
    else if (fdtable[idx].fd == fd)
      {
        err = gpg_error (GPG_ERR_DUP_KEY);
        goto leave;
      }

  if (firstunused == -1)
    {
      /* We need to increase the size of the table.  The approach we
       * take is straightforward to minimize the risk of bugs.  */
      fdtable_item_t newtbl;
      size_t newsize = fdtablesize + 64;

      newtbl = calloc (newsize, sizeof *newtbl);
      if (!newtbl)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      for (idx=0; idx < fdtablesize; idx++)
        newtbl[idx] = fdtable[idx];
      for (; idx < newsize; idx++)
        newtbl[idx].fd = -1;

      free (fdtable);
      fdtable = newtbl;
      idx = fdtablesize;
      fdtablesize = newsize;
    }
  else
    idx = firstunused;

  fdtable[idx].fd = fd;
  fdtable[idx].owner = 0;
  fdtable[idx].active = 0;
  fdtable[idx].done = 0;
  fdtable[idx].for_read = 0;
  fdtable[idx].for_write = 0;
  fdtable[idx].signaled = 0;
  fdtable[idx].closing = 0;
  fdtable[idx].io_cb_running = 0;
  fdtable[idx].io_cb.cb = NULL;
  fdtable[idx].io_cb.value = NULL;
  fdtable[idx].close_notify.handler = NULL;
  fdtable[idx].close_notify.value   = NULL;
  err = 0;

 leave:
  UNLOCK (fdtable_lock);
  return TRACE_ERR (err);
}


/* Add the close notification HANDLER to the table under the key FD.
 * FD must exist.  VALUE is a pointer passed to the handler along with
 * the FD.  */
gpg_error_t
_gpgme_fdtable_add_close_notify (int fd,
                                 fdtable_handler_t handler, void *value)
{
  gpg_error_t err;
  int idx;

  TRACE_BEG  (DEBUG_SYSIO, __func__, NULL, "fd=%d", fd);

  if (fd < 0 )
    return TRACE_ERR (gpg_error (GPG_ERR_INV_ARG));

  LOCK (fdtable_lock);

  for (idx=0; idx < fdtablesize; idx++)
    if (fdtable[idx].fd == fd)
      break;
  if (idx == fdtablesize)
    {
      err = gpg_error (GPG_ERR_NO_KEY);
      goto leave;
    }

  if (fdtable[idx].close_notify.handler)
    {
      err = gpg_error (GPG_ERR_DUP_VALUE);
      goto leave;
    }

  fdtable[idx].close_notify.handler = handler;
  fdtable[idx].close_notify.value = value;
  err = 0;

 leave:
  UNLOCK (fdtable_lock);
  return TRACE_ERR (err);
}


/* Set the I/O callback for the FD.  FD must already exist otherwise
 * GPG_ERR_NO_KEY is returned.  OWNER is the serial of the owning
 * context.  If DIRECTION is 1 the callback wants to read from it; if
 * it is 0 the callback want to write to it.  CB is the actual
 * callback and CB_VALUE the values passed to that callback.  If a
 * callback as already been set GPG_ERR_DUP_VALUE is returned.  To
 * remove the handler, FD and OWNER must be passed as usual but CB be
 * passed as NULL.
 */
gpg_error_t
_gpgme_fdtable_set_io_cb (int fd, uint64_t owner, int direction,
                          gpgme_io_cb_t cb, void *cb_value)
{
  gpg_error_t err;
  int idx;

  TRACE_BEG  (DEBUG_SYSIO, __func__, NULL, "fd=%d ctx=%lu dir=%d",
              fd, (unsigned long)owner, direction);

  if (fd < 0 || !owner)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_ARG));

  LOCK (fdtable_lock);

  if (cb)
    {
      for (idx=0; idx < fdtablesize; idx++)
        if (fdtable[idx].fd == fd)
          break;
      if (idx == fdtablesize)
        {
          err = gpg_error (GPG_ERR_NO_KEY);
          TRACE_LOG ("with_cb: fd=%d owner=%lu", fd, (unsigned long)owner);
          goto leave;
        }

      if (fdtable[idx].io_cb.cb)
        {
          err = gpg_error (GPG_ERR_DUP_VALUE);
          goto leave;
        }

      fdtable[idx].owner = owner;

      fdtable[idx].for_read = (direction == 1);
      fdtable[idx].for_write = (direction == 0);
      fdtable[idx].signaled = 0;

      fdtable[idx].io_cb.cb = cb;
      fdtable[idx].io_cb.value = cb_value;
    }
  else  /* Remove.  */
    {
      /* We compare also the owner as a cross-check.  */
      for (idx=0; idx < fdtablesize; idx++)
        if (fdtable[idx].fd == fd && fdtable[idx].owner == owner)
          break;
      if (idx == fdtablesize)
        {
          err = gpg_error (GPG_ERR_NO_KEY);
          TRACE_LOG ("remove: fd=%d owner=%lu", fd, (unsigned long)owner);
          for (idx=0; idx < fdtablesize; idx++)
            TRACE_LOG ("  TBL: fd=%d owner=%lu", fdtable[idx].fd, (unsigned long)fdtable[idx].owner);
          goto leave;
        }

      fdtable[idx].for_read = 0;
      fdtable[idx].for_write = 0;
      fdtable[idx].signaled = 0;

      fdtable[idx].io_cb.cb = NULL;
      fdtable[idx].io_cb.value = NULL;
      fdtable[idx].owner = 0;
    }
  err = 0;

 leave:
  UNLOCK (fdtable_lock);
  return TRACE_ERR (err);
}


/* Set all FDs of OWNER into the active state.  */
gpg_error_t
_gpgme_fdtable_set_active (uint64_t owner)
{
  int idx;

  TRACE_BEG  (DEBUG_SYSIO, __func__, NULL, "ctx=%lu", (unsigned long)owner);

  if (!owner )
    return TRACE_ERR (gpg_error (GPG_ERR_INV_ARG));

  LOCK (fdtable_lock);

  for (idx=0; idx < fdtablesize; idx++)
    if (fdtable[idx].fd != -1 && fdtable[idx].owner == owner
        && fdtable[idx].io_cb.cb)
      {
        fdtable[idx].active = 1;
        fdtable[idx].done   = 0;
      }

  UNLOCK (fdtable_lock);
  return TRACE_ERR (0);
}


/* Set all FDs of OWNER into the done state.  STATUS and OP_ERR are
 * recorded. */
gpg_error_t
_gpgme_fdtable_set_done (uint64_t owner, gpg_error_t status, gpg_error_t op_err)
{
  int idx;

  TRACE_BEG  (DEBUG_SYSIO, __func__, NULL, "ctx=%lu", (unsigned long)owner);

  if (!owner )
    return TRACE_ERR (gpg_error (GPG_ERR_INV_ARG));

  LOCK (fdtable_lock);

  for (idx=0; idx < fdtablesize; idx++)
    if (fdtable[idx].fd != -1 && fdtable[idx].owner == owner
        && fdtable[idx].active)
      {
        fdtable[idx].active = 0;
        fdtable[idx].done   = 1;
        fdtable[idx].done_status = status;
        fdtable[idx].done_op_err = op_err;
      }

  UNLOCK (fdtable_lock);
  return TRACE_ERR (0);
}


/* Walk over all fds in FDS and copy the signaled flag if set.  It
 * does not clear any signal flag in the global table.  */
void
_gpgme_fdtable_set_signaled (io_select_t fds, unsigned int nfds)
{
  int idx;
  unsigned int n, count;

  if (!nfds)
    return;

  /* FIXME: Highly inefficient code in case of large select lists.  */
  count = 0;
  LOCK (fdtable_lock);
  for (idx=0; idx < fdtablesize; idx++)
    {
      if (fdtable[idx].fd == -1)
        continue;
      for (n = 0; n < nfds; n++)
        if (fdtable[idx].fd == fds[n].fd)
          {
            if (fds[n].signaled && !fdtable[idx].signaled)
              {
                fdtable[idx].signaled = 1;
                count++; /* Only for tracing.  */
              }
            break;
          }
    }
  UNLOCK (fdtable_lock);

  TRACE  (DEBUG_SYSIO, __func__, NULL, "fds newly signaled=%u", count);
}


/* Remove FD from the table after calling the close handler.  Note
 * that at the time the close handler is called the FD has been
 * removed form the table.  Thus the close handler may not access the
 * fdtable anymore and assume that FD is still there.  Callers may
 * want to handle the error code GPG_ERR_NO_KEY which indicates that
 * FD is not anymore or not yet in the table.  */
gpg_error_t
_gpgme_fdtable_remove (int fd)
{
  gpg_error_t err;
  int idx;
  fdtable_handler_t handler;
  void *handlervalue;

  TRACE_BEG  (DEBUG_SYSIO, __func__, NULL, "fd=%d", fd);

  if (fd < 0 )
    return TRACE_ERR (gpg_error (GPG_ERR_INV_ARG));

  LOCK (fdtable_lock);

  for (idx=0; idx < fdtablesize; idx++)
    if (fdtable[idx].fd == fd)
      break;
  if (idx == fdtablesize)
    {
      UNLOCK (fdtable_lock);
      return TRACE_ERR (gpg_error (GPG_ERR_NO_KEY));
    }

  TRACE_LOG ("removal of fd=%d owner=%lu (closing=%d)",
             fdtable[idx].fd, (unsigned long)fdtable[idx].owner,
             fdtable[idx].closing);

  handler = fdtable[idx].close_notify.handler;
  fdtable[idx].close_notify.handler = NULL;
  handlervalue = fdtable[idx].close_notify.value;
  fdtable[idx].close_notify.value = NULL;

  /* The handler might call into the fdtable again, so of we have a
   * handler we can't immediately close it but instead record the fact
   * and remove the entry from the table only after the handler has
   * been run.  */
  if (handler)
    fdtable[idx].closing = 1;
  else if (!fdtable[idx].closing)
    fdtable[idx].fd = -1;

  UNLOCK (fdtable_lock);

  if (handler)
    {
      err = handler (fd, handlervalue);
      LOCK (fdtable_lock);
      TRACE_LOG ("final removal of fd=%d owner=%lu (closing=%d)",
                 fdtable[idx].fd, (unsigned long)fdtable[idx].owner,
                 fdtable[idx].closing);
      fdtable[idx].fd = -1;
      UNLOCK (fdtable_lock);
    }
  else
    err = 0;

  return TRACE_ERR (err);
}


/* Return the number of active I/O callbacks for OWNER or for all if
 * OWNER is 0.  */
unsigned int
_gpgme_fdtable_io_cb_count (uint64_t owner)
{
  int idx;
  unsigned int count = 0;

  LOCK (fdtable_lock);
  for (idx=0; idx < fdtablesize; idx++)
    if (fdtable[idx].fd != -1 && (!owner || fdtable[idx].owner == owner))
      count++;
  UNLOCK (fdtable_lock);

  TRACE  (DEBUG_SYSIO, __func__, NULL, "ctx=%lu count=%u",
          (unsigned long)owner, count);
  return count;
}


/* Run all signaled IO callbacks of OWNER or all signaled callbacks if
 * OWNER is 0.  Returns an error code on the first real error
 * encountered.  If R_OP_ERR is not NULL an optional operational error
 * can be stored tehre.  For EOF the respective flags are set.  */
gpg_error_t
_gpgme_fdtable_run_io_cbs (uint64_t owner, gpg_error_t *r_op_err)
{
  gpg_error_t err;
  int idx;
  int fd;
  gpgme_io_cb_t iocb;
  struct io_cb_data iocb_data;
  uint64_t serial;
  unsigned int cb_count;
  gpgme_ctx_t actx;

  if (r_op_err)
    *r_op_err = 0;

  TRACE_BEG  (DEBUG_SYSIO, __func__, NULL, "ctx=%lu", owner);

  for (;;)
    {
      fd = -1;
      LOCK (fdtable_lock);
      for (idx=0; idx < fdtablesize; idx++)
        if (fdtable[idx].fd != -1 && (!owner || fdtable[idx].owner == owner)
            && fdtable[idx].signaled)
          {
            fd = fdtable[idx].fd;
            serial = fdtable[idx].owner;
            iocb = fdtable[idx].io_cb.cb;
            iocb_data.handler_value = fdtable[idx].io_cb.value;
            iocb_data.op_err = 0;
            fdtable[idx].signaled = 0;
            if (iocb)
              {
                fdtable[idx].io_cb_running = 1;
                break;
              }
          }
      UNLOCK (fdtable_lock);
      if (fd == -1)
        break;  /* No more callbacks found.  */

      /* If the context object is still valid and has not been
       * canceled, we run the I/O callback.  */
      err = _gpgme_get_ctx (serial, &actx);
      if (!err)
        {
          err = iocb (&iocb_data, fd);
          if (err)
            TRACE_LOG ("iocb(fd=%d) err=%s", fd, gpg_strerror (err));
        }

      /* Clear the running flag and while we are at it also count the
       * remaining callbacks.  */
      cb_count = 0;
      LOCK (fdtable_lock);
      for (idx=0; idx < fdtablesize; idx++)
        {
          if (fdtable[idx].fd == -1)
            continue;
          if (fdtable[idx].fd == fd)
            fdtable[idx].io_cb_running = 0;
          if (fdtable[idx].owner == serial)
            cb_count++;
        }
      UNLOCK (fdtable_lock);

      /* Handle errors or success from the IO callback.  In the error
       * case we close all fds belonging to the same context.  In the
       * success case we check whether any callback is left and only
       * if that is not the case, tell the engine that we are done.
       * The latter indirectly sets the fd into the done state.  */
      if (err)
        {
          _gpgme_cancel_with_err (serial, err, 0);
          return TRACE_ERR (err);
        }
      else if (iocb_data.op_err)
        {
          /* An operational error occurred.  Cancel the current
           * operation but not the session, and signal it.  */
          _gpgme_cancel_with_err (serial, 0, iocb_data.op_err);

          /* NOTE: This relies on the operational error being
           * generated after the operation really has completed, for
           * example after no further status line output is generated.
           * Otherwise the following I/O will spill over into the next
           * operation. */
          if (r_op_err)
            *r_op_err = iocb_data.op_err;
          return TRACE_ERR (0);
        }
      else if (!cb_count && actx)
        {
          struct gpgme_io_event_done_data data = { 0, 0 };
          _gpgme_engine_io_event (actx->engine, GPGME_EVENT_DONE, &data);
        }
    }

  return TRACE_ERR (0);
}


/* Retrieve a list of file descriptors owned by OWNER, or with OWNER
 * being 0 of all fds, and store that list as a new array at R_FDS.
 * Return the number of FDS in that list or 0 if none were selected.
 * FLAGS give further selection flags:
 *   FDTABLE_FLAG_ACTIVE       - Only those with the active flag set.
 *   FDTABLE_FLAG_DONE         - Only those with the done flag set.
 *   FDTABLE_FLAG_FOR_READ     - Only those with the readable FDs.
 *   FDTABLE_FLAG_FOR_WRITE    - Only those with the writable FDs.
 *   FDTABLE_FLAG_SIGNALED     - Only those with the signaled flag set.
 *   FDTABLE_FLAG_NOT_SIGNALED - Only those with the signaled flag cleared.
 *   FDTABLE_FLAG_CLEAR        - Clear the signaled flag..
 */
unsigned int
_gpgme_fdtable_get_fds (io_select_t *r_fds, uint64_t owner, unsigned int flags)
{
  int idx;
  unsigned int count = 0;
  io_select_t fds;

  *r_fds = NULL;
  gpg_err_set_errno (0);
  /* We take an easy approach and allocate the array at the size of
   * the entire fdtable.  */
  fds = calloc (fdtablesize, sizeof *fds);
  if (!fds)
    return 0;

  LOCK (fdtable_lock);
  for (idx=0; idx < fdtablesize; idx++)
    if (fdtable[idx].fd != -1 && (!owner || fdtable[idx].owner == owner))
      {
        if ((flags & FDTABLE_FLAG_ACTIVE) && !fdtable[idx].active)
          continue;
        if ((flags & FDTABLE_FLAG_DONE) && !fdtable[idx].done)
          continue;
        if ((flags & FDTABLE_FLAG_FOR_READ) && !fdtable[idx].for_read)
          continue;
        if ((flags & FDTABLE_FLAG_FOR_WRITE) && !fdtable[idx].for_write)
          continue;
        if ((flags & FDTABLE_FLAG_SIGNALED) && !fdtable[idx].signaled)
          continue;
        if ((flags & FDTABLE_FLAG_NOT_SIGNALED) && fdtable[idx].signaled)
          continue;

        if (fdtable[idx].io_cb_running || fdtable[idx].closing)
          continue; /* The callback has not yet finished or we are
                     * already closing.  Does not make sense to allow
                     * selecting on it.  */

        fds[count].fd = fdtable[idx].fd;
        fds[count].for_read = fdtable[idx].for_read;
        fds[count].for_write = fdtable[idx].for_write;
        fds[count].signaled =
          (flags & FDTABLE_FLAG_SIGNALED)? 0 : fdtable[idx].signaled;

        count++;
      }

  UNLOCK (fdtable_lock);
  *r_fds = fds;

  TRACE  (DEBUG_SYSIO, __func__, NULL, "ctx=%lu count=%u",
          (unsigned long)owner, count);
  return count;
}


/* If OWNER is 0 return the status info of the first fd with the done
 * flag set.  If OWNER is not 0 search for a matching owner with the
 * done flag set and return its status info.  Returns the serial
 * number of the context found.  */
uint64_t
_gpgme_fdtable_get_done (uint64_t owner,
                         gpg_error_t *r_status, gpg_error_t *r_op_err)
{
  uint64_t serial = 0;
  int idx;

  TRACE_BEG (DEBUG_SYSIO, __func__, NULL, "ctx=%lu", (unsigned long)owner);

  LOCK (fdtable_lock);

  for (idx=0; idx < fdtablesize; idx++)
    if (fdtable[idx].fd != -1 && (!owner || fdtable[idx].owner == owner)
        && fdtable[idx].done)
      {
        /* Found.  If an owner has been given also clear the done
         * flags from all other fds of this owner.  Note that they
         * have the same status info anyway.  */
        *r_status = fdtable[idx].done_status;
        *r_op_err = fdtable[idx].done_op_err;
        fdtable[idx].done = 0;
        serial = fdtable[idx].owner;
        if (owner)
          {
            for (; idx < fdtablesize; idx++)
              if (fdtable[idx].fd != -1 && fdtable[idx].owner == owner)
                fdtable[idx].done = 0;
          }
        break;
      }

  UNLOCK (fdtable_lock);

  TRACE_SUC ("ctx=%lu", (unsigned long)serial);
  return serial;
}
