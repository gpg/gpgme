/* edit.c - Key edit functions.
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
#include <stdlib.h>
#include <assert.h>

#include "util.h"
#include "context.h"
#include "ops.h"


struct edit_result
{
  GpgmeEditCb fnc;
  void *fnc_value;
};
typedef struct edit_result *EditResult;

static GpgmeError
edit_status_handler (GpgmeCtx ctx, GpgmeStatusCode status, char *args)
{
  EditResult result;
  GpgmeError err = _gpgme_passphrase_status_handler (ctx, status, args);
  if (err)
    return err;

  err = _gpgme_progress_status_handler (ctx, status, args);
  if (err)
    return err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_EDIT, (void **) &result,
			       -1, NULL);
  if (err)
    return err;
  assert (result);

  return (*result->fnc) (result->fnc_value, status, args, NULL);
}


static GpgmeError
command_handler (void *opaque, GpgmeStatusCode status, const char *args,
		 const char **result_r)
{
  EditResult result;
  GpgmeError err;
  GpgmeCtx ctx = opaque;

  *result_r = NULL;
  err = _gpgme_passphrase_command_handler (ctx, status, args, result_r);
  if (err)
    return err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_EDIT, (void **) &result,
			       -1, NULL);
  if (err)
    return err;
  assert (result);

  if (!*result_r)
    err = (*result->fnc) (result->fnc_value, status, args, result_r);

  return err;
}


static GpgmeError
_gpgme_op_edit_start (GpgmeCtx ctx, int synchronous,
		      GpgmeKey key,
		      GpgmeEditCb fnc, void *fnc_value,
		      GpgmeData out)
{
  EditResult result;
  GpgmeError err = 0;

  if (!fnc)
    return GPGME_Invalid_Value;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    goto leave;

  err = _gpgme_op_data_lookup (ctx, OPDATA_EDIT, (void **) &result,
			       sizeof (*result), NULL);
  if (err)
    goto leave;

  result->fnc = fnc;
  result->fnc_value = fnc_value;

  /* Check the supplied data.  */
  if (!out)
    {
      err = GPGME_Invalid_Value;
      goto leave;
    }

  err = _gpgme_engine_set_command_handler (ctx->engine, command_handler,
					   ctx, out);
  if (err)
    goto leave;

  _gpgme_engine_set_status_handler (ctx->engine, edit_status_handler, ctx);

  _gpgme_engine_set_verbosity (ctx->engine, ctx->verbosity);

  err = _gpgme_engine_op_edit (ctx->engine, key, out, ctx);

 leave:
  if (err)
    {
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
