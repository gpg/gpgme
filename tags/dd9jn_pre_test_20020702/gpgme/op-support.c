/* op-support.c 
 *      Copyright (C) 2002 g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>

#include "gpgme.h"
#include "context.h"
#include "ops.h"

GpgmeError
_gpgme_op_reset (GpgmeCtx ctx, int synchronous)
{
  GpgmeError err = 0;
  struct GpgmeIOCbs io_cbs;

  fail_on_pending_request (ctx);
  ctx->pending = 1;

  _gpgme_release_result (ctx);

  /* Create an engine object.  */
  _gpgme_engine_release (ctx->engine);
  ctx->engine = NULL;
  err = _gpgme_engine_new (ctx->use_cms ? GPGME_PROTOCOL_CMS
			   : GPGME_PROTOCOL_OpenPGP, &ctx->engine);
  if (err)
    return err;

  if (synchronous)
    {
      io_cbs.add = _gpgme_add_io_cb;
      io_cbs.add_priv = &ctx->fdt;
      io_cbs.remove = _gpgme_remove_io_cb;
      io_cbs.event = _gpgme_op_event_cb;
      io_cbs.event_priv = ctx;
    }
  else if (! ctx->io_cbs.add)
    {
      io_cbs.add = _gpgme_add_io_cb;
      io_cbs.add_priv = NULL;
      io_cbs.remove = _gpgme_remove_io_cb;
      io_cbs.event = _gpgme_wait_event_cb;
      io_cbs.event_priv = ctx;
    }
  else
    {
      io_cbs = ctx->io_cbs;
      io_cbs.event = _gpgme_op_event_cb;
      io_cbs.event_priv = ctx;
    }
  _gpgme_engine_set_io_cbs (ctx->engine, &io_cbs);
  return err;
}
