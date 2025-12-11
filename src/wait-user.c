/* wait-user.c
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004, 2005 g10 Code GmbH
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
#include <assert.h>

#include "util.h"
#include "gpgme.h"
#include "context.h"
#include "priv-io.h"
#include "wait.h"
#include "ops.h"
#include "debug.h"


/* The user event loops are used for all asynchronous operations for
   which a user callback is defined.  */


/* Internal I/O Callbacks.  */

gpgme_error_t
_gpgme_user_io_cb_handler (void *data, int fd)
{
  gpgme_error_t err = 0;
  gpgme_error_t op_err = 0;
  struct tag *tag = (struct tag *) data;
  gpgme_ctx_t ctx;

  (void)fd;

  assert (data);
  ctx = tag->ctx;
  assert (ctx);

  LOCK (ctx->lock);
  if (ctx->canceled)
    err = gpg_error (GPG_ERR_CANCELED);
  UNLOCK (ctx->lock);

  if (! err)
    err = _gpgme_run_io_cb (&ctx->fdt.fds[tag->idx], 0, &op_err);
  if (err || op_err)
    _gpgme_cancel_with_err (ctx, err, op_err);
  else
    {
      unsigned int i;

      for (i = 0; i < ctx->fdt.size; i++)
	if (ctx->fdt.fds[i].fd != -1)
	  break;

      if (i == ctx->fdt.size)
	{
	  struct gpgme_io_event_done_data done_data;

	  done_data.err = 0;
	  done_data.op_err = 0;
	  _gpgme_engine_io_event (ctx->engine, GPGME_EVENT_DONE, &done_data);
	}
    }
  return 0;
}


/* Register the file descriptor FD with the handler FNC (which gets
   FNC_DATA as its first argument) for the direction DIR.  DATA should
   be the context for which the fd is added.  R_TAG will hold the tag
   that can be used to remove the fd.  */
gpgme_error_t
_gpgme_wait_user_add_io_cb (void *data, int fd, int dir, gpgme_io_cb_t fnc,
			    void *fnc_data, void **r_tag)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) data;
  struct tag *tag;
  gpgme_error_t err;

  assert (ctx);
  err = _gpgme_add_io_cb (data, fd, dir, fnc, fnc_data, r_tag);
  if (err)
    return err;
  tag = *r_tag;
  assert (tag);
  err = (*ctx->io_cbs.add) (ctx->io_cbs.add_priv, fd, dir,
			    _gpgme_user_io_cb_handler, *r_tag,
			    &tag->user_tag);
  if (err)
    _gpgme_remove_io_cb (*r_tag);
  return err;
}


void
_gpgme_wait_user_remove_io_cb (void *data)
{
  struct tag *tag = (struct tag *) data;
  gpgme_ctx_t ctx;

  assert (tag);
  ctx = tag->ctx;

  (*ctx->io_cbs.remove) (tag->user_tag);
  _gpgme_remove_io_cb (data);
}


void
_gpgme_wait_user_event_cb (void *data, gpgme_event_io_t type, void *type_data)
{
  gpgme_ctx_t ctx = data;

  if (ctx->io_cbs.event)
    (*ctx->io_cbs.event) (ctx->io_cbs.event_priv, type, type_data);
}
