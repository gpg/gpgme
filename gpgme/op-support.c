/* op-support.c 
   Copyright (C) 2002, 2003 g10 Code GmbH

   This file is part of GPGME.
 
   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with GPGME; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "gpgme.h"
#include "context.h"
#include "ops.h"

/* type is: 0: asynchronous operation (use global or user event loop).
            1: synchronous operation (always use private event loop).
            2: asynchronous private operation (use private or user
            event loop).  */
GpgmeError
_gpgme_op_reset (GpgmeCtx ctx, int type)
{
  GpgmeError err = 0;
  struct GpgmeIOCbs io_cbs;

  fail_on_pending_request (ctx);
  _gpgme_release_result (ctx);

  /* Create an engine object.  */
  _gpgme_engine_release (ctx->engine);
  ctx->engine = NULL;
  ctx->pending = 1;
  err = _gpgme_engine_new (ctx->use_cms ? GPGME_PROTOCOL_CMS
			   : GPGME_PROTOCOL_OpenPGP, &ctx->engine);
  if (err)
    return err;

  if (type == 1 || (type == 2 && !ctx->io_cbs.add))
    {
      /* Use private event loop.  */
      io_cbs.add = _gpgme_add_io_cb;
      io_cbs.add_priv = ctx;
      io_cbs.remove = _gpgme_remove_io_cb;
      io_cbs.event = _gpgme_wait_private_event_cb;
      io_cbs.event_priv = ctx;
    }
  else if (! ctx->io_cbs.add)
    {
      /* Use global event loop.  */
      io_cbs.add = _gpgme_add_io_cb;
      io_cbs.add_priv = ctx;
      io_cbs.remove = _gpgme_remove_io_cb;
      io_cbs.event = _gpgme_wait_global_event_cb;
      io_cbs.event_priv = ctx;
    }
  else
    {
      /* Use user event loop.  */
      io_cbs.add = _gpgme_wait_user_add_io_cb;
      io_cbs.add_priv = ctx;
      io_cbs.remove = _gpgme_wait_user_remove_io_cb;
      io_cbs.event = _gpgme_wait_user_event_cb;
      io_cbs.event_priv = ctx;
    }
  _gpgme_engine_set_io_cbs (ctx->engine, &io_cbs);
  return err;
}
