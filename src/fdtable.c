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

  handler = fdtable[idx].close_notify.handler;
  fdtable[idx].close_notify.handler = NULL;
  handlervalue = fdtable[idx].close_notify.value;
  fdtable[idx].close_notify.value = NULL;
  fdtable[idx].fd = -1;

  UNLOCK (fdtable_lock);

  err = handler? handler (fd, handlervalue) : 0;

  return TRACE_ERR (err);
}
