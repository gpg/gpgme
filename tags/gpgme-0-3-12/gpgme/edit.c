/* edit.c - key edit functions
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "util.h"
#include "context.h"
#include "ops.h"


struct edit_result_s
{
  GpgmeEditCb fnc;
  void *fnc_value;
};

void
_gpgme_release_edit_result (EditResult result)
{
  if (!result)
    return;
  xfree (result);
}

void
_gpgme_edit_status_handler (GpgmeCtx ctx, GpgmeStatusCode status, char *args)
{
  _gpgme_passphrase_status_handler (ctx, status, args);

  if (ctx->error)
    return;

  ctx->error = (*ctx->result.edit->fnc) (ctx->result.edit->fnc_value, status, args, NULL);
}

static const char *
command_handler (void *opaque, GpgmeStatusCode status, const char *args)
{
  GpgmeCtx ctx = opaque;
  const char *result;

  result = _gpgme_passphrase_command_handler (ctx, status, args);

  if (!result)
    ctx->error = (*ctx->result.edit->fnc) (ctx->result.edit->fnc_value, status, args, &result);

  return result;
}

static GpgmeError
_gpgme_op_edit_start (GpgmeCtx ctx, int synchronous,
		      GpgmeKey key,
		      GpgmeEditCb fnc, void *fnc_value,
		      GpgmeData out)
{
  GpgmeError err = 0;

  if (!fnc)
    return mk_error (Invalid_Value);

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    goto leave;

  assert (!ctx->result.edit);
  ctx->result.edit = xtrymalloc (sizeof *ctx->result.edit);
  if (!ctx->result.edit)
    {
      err = mk_error (Out_Of_Core);
      goto leave;
    }
  ctx->result.edit->fnc = fnc;
  ctx->result.edit->fnc_value = fnc_value;

  /* Check the supplied data.  */
  if (!out || gpgme_data_get_type (out) != GPGME_DATA_TYPE_NONE)
    {
      err = mk_error (Invalid_Value);
      goto leave;
    }
  _gpgme_data_set_mode (out, GPGME_DATA_MODE_IN);

  err = _gpgme_engine_set_command_handler (ctx->engine, command_handler,
					   ctx, out);
  if (err)
    goto leave;

  _gpgme_engine_set_status_handler (ctx->engine, _gpgme_edit_status_handler,
				    ctx);

  _gpgme_engine_set_verbosity (ctx->engine, ctx->verbosity);

  _gpgme_engine_op_edit (ctx->engine, key, out, ctx);

  /* And kick off the process.  */
  err = _gpgme_engine_start (ctx->engine, ctx);
  
 leave:
  if (err)
    {
      ctx->pending = 0; 
      _gpgme_engine_release (ctx->engine);
      ctx->engine = NULL;
    }
  return err;
}

GpgmeError
gpgme_op_edit_start (GpgmeCtx ctx,
		     GpgmeKey key,
		     GpgmeEditCb fnc, void *fnc_value,
		     GpgmeData out)
{
  return _gpgme_op_edit_start (ctx, 0, key, fnc, fnc_value, out);
}

/**
 * gpgme_op_edit:
 * @ctx: The context
 * @key: The key to be edited.
 * @fnc: An edit callback handler.
 * @fnc_value: To be passed to @fnc as first arg.
 * @out: The output.
 * 
 * Return value: 0 on success or an error code.
 **/
GpgmeError
gpgme_op_edit (GpgmeCtx ctx,
	       GpgmeKey key,
	       GpgmeEditCb fnc, void *fnc_value,
	       GpgmeData out)
{
  GpgmeError err = _gpgme_op_edit_start (ctx, 1, key, fnc, fnc_value, out);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return err;
}
