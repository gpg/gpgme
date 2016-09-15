/* edit.c - Key edit function.
   Copyright (C) 2002, 2003, 2004 g10 Code GmbH

   This file is part of GPGME.

   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>

#include "gpgme.h"
#include "debug.h"
#include "context.h"
#include "ops.h"
#include "util.h"



typedef struct
{
  /* The user callback function and its hook value.  */
  gpgme_interact_cb_t fnc;
  gpgme_edit_cb_t fnc_old;
  void *fnc_value;
} *op_data_t;


static gpgme_error_t
edit_status_handler (void *priv, gpgme_status_code_t status, char *args)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_passphrase_status_handler (priv, status, args);
  if (err)
    return err;

  err = _gpgme_progress_status_handler (priv, status, args);
  if (err)
    return err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_EDIT, &hook, -1, NULL);
  opd = hook;
  if (err)
    return err;

  if (opd->fnc_old)
    return (*opd->fnc_old) (opd->fnc_value, status, args, -1);

  return (*opd->fnc) (opd->fnc_value, _gpgme_status_to_string (status),
                      args, -1);
}


static gpgme_error_t
command_handler (void *priv, gpgme_status_code_t status, const char *args,
		 int fd, int *processed_r)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  gpgme_error_t err;
  int processed = 0;

  if (ctx->passphrase_cb)
    {
      err = _gpgme_passphrase_command_handler (ctx, status, args,
					       fd, &processed);
      if (err)
	return err;
    }
  else
    err = 0;

  if (!processed)
    {
      void *hook;
      op_data_t opd;

      err = _gpgme_op_data_lookup (ctx, OPDATA_EDIT, &hook, -1, NULL);
      opd = hook;
      if (err)
	return err;

      if (opd->fnc_old)
        err = (*opd->fnc_old) (opd->fnc_value, status, args, fd);
      else
        err = (*opd->fnc) (opd->fnc_value, _gpgme_status_to_string (status),
                           args, fd);

      if (gpg_err_code (err) == GPG_ERR_FALSE)
        err = 0;
      else
        processed = 1;
    }

  *processed_r = processed;
  return err;
}


static gpgme_error_t
interact_start (gpgme_ctx_t ctx, int synchronous, gpgme_key_t key,
                unsigned int flags,
                gpgme_interact_cb_t fnc, void *fnc_value, gpgme_data_t out)
{
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  if (!fnc || !out)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = _gpgme_op_data_lookup (ctx, OPDATA_EDIT, &hook, sizeof (*opd), NULL);
  opd = hook;
  if (err)
    return err;

  opd->fnc = fnc;
  opd->fnc_old = NULL;
  opd->fnc_value = fnc_value;

  err = _gpgme_engine_set_command_handler (ctx->engine, command_handler,
					   ctx, out);
  if (err)
    return err;

  _gpgme_engine_set_status_handler (ctx->engine, edit_status_handler, ctx);

  return _gpgme_engine_op_edit (ctx->engine,
                                (flags & GPGME_INTERACT_CARD)? 1: 0,
                                key, out, ctx);
}


gpgme_error_t
gpgme_op_interact_start (gpgme_ctx_t ctx, gpgme_key_t key, unsigned int flags,
                         gpgme_interact_cb_t fnc, void *fnc_value,
                         gpgme_data_t out)
{
  gpgme_error_t err;

  TRACE_BEG5 (DEBUG_CTX, "gpgme_op_interact_start", ctx,
	      "key=%p flags=0x%x fnc=%p fnc_value=%p, out=%p",
	      key, flags,fnc, fnc_value, out);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = interact_start (ctx, 0, key, flags, fnc, fnc_value, out);
  return err;
}


gpgme_error_t
gpgme_op_interact (gpgme_ctx_t ctx, gpgme_key_t key, unsigned int flags,
                   gpgme_interact_cb_t fnc, void *fnc_value,
                   gpgme_data_t out)
{
  gpgme_error_t err;

  TRACE_BEG5 (DEBUG_CTX, "gpgme_op_interact", ctx,
	      "key=%p flags=0x%x fnc=%p fnc_value=%p, out=%p",
	      key, flags,fnc, fnc_value, out);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = interact_start (ctx, 1, key, flags, fnc, fnc_value, out);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return err;
}




/* The deprectated interface.  */
static gpgme_error_t
edit_start (gpgme_ctx_t ctx, int synchronous, int type, gpgme_key_t key,
	    gpgme_edit_cb_t fnc, void *fnc_value, gpgme_data_t out)
{
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  if (!fnc || !out)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = _gpgme_op_data_lookup (ctx, OPDATA_EDIT, &hook, sizeof (*opd), NULL);
  opd = hook;
  if (err)
    return err;

  opd->fnc = NULL;
  opd->fnc_old = fnc;
  opd->fnc_value = fnc_value;

  err = _gpgme_engine_set_command_handler (ctx->engine, command_handler,
					   ctx, out);
  if (err)
    return err;

  _gpgme_engine_set_status_handler (ctx->engine, edit_status_handler, ctx);

  return _gpgme_engine_op_edit (ctx->engine, type, key, out, ctx);
}


gpgme_error_t
gpgme_op_edit_start (gpgme_ctx_t ctx, gpgme_key_t key,
		     gpgme_edit_cb_t fnc, void *fnc_value, gpgme_data_t out)
{
  gpgme_error_t err;

  TRACE_BEG5 (DEBUG_CTX, "gpgme_op_edit_start", ctx,
	      "key=%p (%s), fnc=%p fnc_value=%p, out=%p", key,
	      (key && key->subkeys && key->subkeys->fpr) ?
	      key->subkeys->fpr : "invalid", fnc, fnc_value, out);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = edit_start (ctx, 0, 0, key, fnc, fnc_value, out);
  return err;
}


/* Edit the key KEY.  Send status and command requests to FNC and
   output of edit commands to OUT.  */
gpgme_error_t
gpgme_op_edit (gpgme_ctx_t ctx, gpgme_key_t key,
	       gpgme_edit_cb_t fnc, void *fnc_value, gpgme_data_t out)
{
  gpgme_error_t err;

  TRACE_BEG5 (DEBUG_CTX, "gpgme_op_edit", ctx,
	      "key=%p (%s), fnc=%p fnc_value=%p, out=%p", key,
	      (key && key->subkeys && key->subkeys->fpr) ?
	      key->subkeys->fpr : "invalid", fnc, fnc_value, out);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = edit_start (ctx, 1, 0, key, fnc, fnc_value, out);

  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}


gpgme_error_t
gpgme_op_card_edit_start (gpgme_ctx_t ctx, gpgme_key_t key,
			  gpgme_edit_cb_t fnc, void *fnc_value,
			  gpgme_data_t out)
{
  gpgme_error_t err;

  TRACE_BEG5 (DEBUG_CTX, "gpgme_op_card_edit_start", ctx,
	      "key=%p (%s), fnc=%p fnc_value=%p, out=%p", key,
	      (key && key->subkeys && key->subkeys->fpr) ?
	      key->subkeys->fpr : "invalid", fnc, fnc_value, out);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = edit_start (ctx, 0, 1, key, fnc, fnc_value, out);
  return err;
}


/* Edit the card for the key KEY.  Send status and command requests to
   FNC and output of edit commands to OUT.  */
gpgme_error_t
gpgme_op_card_edit (gpgme_ctx_t ctx, gpgme_key_t key,
		    gpgme_edit_cb_t fnc, void *fnc_value, gpgme_data_t out)
{
  gpgme_error_t err;

  TRACE_BEG5 (DEBUG_CTX, "gpgme_op_card_edit", ctx,
	      "key=%p (%s), fnc=%p fnc_value=%p, out=%p", key,
	      (key && key->subkeys && key->subkeys->fpr) ?
	      key->subkeys->fpr : "invalid", fnc, fnc_value, out);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = edit_start (ctx, 1, 1, key, fnc, fnc_value, out);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}
