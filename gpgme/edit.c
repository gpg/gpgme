/* edit.c - Key edit function.
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

#include "gpgme.h"
#include "context.h"
#include "ops.h"


typedef struct
{
  /* The user callback function and its hook value.  */
  GpgmeEditCb fnc;
  void *fnc_value;
} *op_data_t;


static GpgmeError
edit_status_handler (void *priv, GpgmeStatusCode status, char *args)
{
  GpgmeCtx ctx = (GpgmeCtx) priv;
  op_data_t opd;

  return _gpgme_passphrase_status_handler (priv, status, args)
    || _gpgme_progress_status_handler (priv, status, args)
    || _gpgme_op_data_lookup (ctx, OPDATA_EDIT, (void **) &opd, -1, NULL)
    || (*opd->fnc) (opd->fnc_value, status, args, NULL);
}


static GpgmeError
command_handler (void *priv, GpgmeStatusCode status, const char *args,
		 const char **result)
{
  GpgmeCtx ctx = (GpgmeCtx) priv;
  GpgmeError err;
  op_data_t opd;

  *result = NULL;
  if (ctx->passphrase_cb)
    {
      err = _gpgme_passphrase_command_handler (ctx, status, args, result);
      if (err)
	return err;
    }

  if (!*result)
    {
      err = _gpgme_op_data_lookup (ctx, OPDATA_EDIT, (void **) &opd, -1, NULL);
      if (err)
	return err;

      return (*opd->fnc) (opd->fnc_value, status, args, result);
    }
  return 0;
}


static GpgmeError
edit_start (GpgmeCtx ctx, int synchronous, GpgmeKey key,
	    GpgmeEditCb fnc, void *fnc_value, GpgmeData out)
{
  GpgmeError err;
  op_data_t opd;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  if (!fnc || !out)
    return GPGME_Invalid_Value;

  err = _gpgme_op_data_lookup (ctx, OPDATA_EDIT, (void **) &opd,
			       sizeof (*opd), NULL);
  if (err)
    return err;

  opd->fnc = fnc;
  opd->fnc_value = fnc_value;

  err = _gpgme_engine_set_command_handler (ctx->engine, command_handler,
					   ctx, out);
  if (err)
    return err;

  _gpgme_engine_set_status_handler (ctx->engine, edit_status_handler, ctx);

  return _gpgme_engine_op_edit (ctx->engine, key, out, ctx);
}


GpgmeError
gpgme_op_edit_start (GpgmeCtx ctx, GpgmeKey key,
		     GpgmeEditCb fnc, void *fnc_value, GpgmeData out)
{
  return edit_start (ctx, 0, key, fnc, fnc_value, out);
}


/* Edit the key KEY.  Send status and command requests to FNC and
   output of edit commands to OUT.  */
GpgmeError
gpgme_op_edit (GpgmeCtx ctx, GpgmeKey key,
	       GpgmeEditCb fnc, void *fnc_value, GpgmeData out)
{
  GpgmeError err = edit_start (ctx, 1, key, fnc, fnc_value, out);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return err;
}
