/* wait-private.c
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
#include <errno.h>

#include "gpgme.h"
#include "context.h"
#include "wait.h"
#include "ops.h"
#include "util.h"
#include "priv-io.h"
#include "debug.h"


/* The private event loops are used for all blocking operations, and
   for the key and trust item listing operations.  They are completely
   separated from each other.  */


/* Internal I/O callback functions.  */

/* The add_io_cb and remove_io_cb handlers are shared with the global
   event loops.  */

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
    }
}


/* If COND is a null pointer, wait until the blocking operation in CTX
   finished and return its error value.  Otherwise, wait until COND is
   satisfied or the operation finished.  */
gpgme_error_t
_gpgme_wait_on_condition (gpgme_ctx_t ctx, volatile int *cond,
			  gpgme_error_t *op_err_p)
{
  gpgme_error_t err = 0;
  int hang = 1;

  if (op_err_p)
    *op_err_p = 0;

  do
    {
      int nr = _gpgme_io_select (ctx->fdt.fds, ctx->fdt.size, 0);
      unsigned int i;

      if (nr < 0)
	{
	  /* An error occurred.  Close all fds in this context, and
	     signal it.  */
	  err = gpg_error_from_syserror ();
          _gpgme_cancel_with_err (ctx, err, 0);

	  return err;
	}

      for (i = 0; i < ctx->fdt.size && nr; i++)
	{
	  if (ctx->fdt.fds[i].fd != -1 && ctx->fdt.fds[i].signaled)
	    {
	      gpgme_error_t op_err = 0;

	      ctx->fdt.fds[i].signaled = 0;
	      assert (nr);
	      nr--;

	      LOCK (ctx->lock);
	      if (ctx->canceled)
		err = gpg_error (GPG_ERR_CANCELED);
	      UNLOCK (ctx->lock);

	      if (!err)
		err = _gpgme_run_io_cb (&ctx->fdt.fds[i], 0, &op_err);
	      if (err)
		{
		  /* An error occurred.  Close all fds in this context,
		     and signal it.  */
		  _gpgme_cancel_with_err (ctx, err, 0);

		  return err;
		}
	      else if (op_err)
		{
		  /* An operational error occurred.  Cancel the current
		     operation but not the session, and signal it.  */
		  _gpgme_cancel_with_err (ctx, 0, op_err);

		  /* NOTE: This relies on the operational error being
		     generated after the operation really has
		     completed, for example after no further status
		     line output is generated.  Otherwise the
		     following I/O will spill over into the next
		     operation.  */
		  if (op_err_p)
		    *op_err_p = op_err;
		  return 0;
		}
	    }
	}

      for (i = 0; i < ctx->fdt.size; i++)
	if (ctx->fdt.fds[i].fd != -1)
	  break;
      if (i == ctx->fdt.size)
	{
	  struct gpgme_io_event_done_data data;
	  data.err = 0;
	  data.op_err = 0;
	  _gpgme_engine_io_event (ctx->engine, GPGME_EVENT_DONE, &data);
	  hang = 0;
	}
      if (cond && *cond)
	hang = 0;
    }
  while (hang);

  return 0;
}


/* Wait until the blocking operation in context CTX has finished and
   return the error value.  This variant can not be used for
   session-based protocols.  */
gpgme_error_t
_gpgme_wait_one (gpgme_ctx_t ctx)
{
  return _gpgme_wait_on_condition (ctx, NULL, NULL);
}

/* Wait until the blocking operation in context CTX has finished and
   return the error value.  This is the right variant to use for
   sesion-based protocols.  */
gpgme_error_t
_gpgme_wait_one_ext (gpgme_ctx_t ctx, gpgme_error_t *op_err)
{
  return _gpgme_wait_on_condition (ctx, NULL, op_err);
}
