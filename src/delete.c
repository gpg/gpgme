/* delete.c - Delete a key.
   Copyright (C) 2001, 2002, 2003, 2004 g10 Code GmbH

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
#include <errno.h>

#include "debug.h"
#include "gpgme.h"
#include "context.h"
#include "ops.h"


static gpgme_error_t
delete_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  (void)priv;

  if (code == GPGME_STATUS_DELETE_PROBLEM)
    {
      enum delete_problem
	{
	  DELETE_No_Problem = 0,
	  DELETE_No_Such_Key = 1,
	  DELETE_Must_Delete_Secret_Key = 2,
	  DELETE_Ambiguous_Specification = 3
	};
      long problem;
      char *tail;

      gpg_err_set_errno (0);
      problem = strtol (args, &tail, 0);
      if (errno || (*tail && *tail != ' '))
	return trace_gpg_error (GPG_ERR_INV_ENGINE);

      switch (problem)
	{
	case DELETE_No_Problem:
	  break;

	case DELETE_No_Such_Key:
	  return gpg_error (GPG_ERR_NO_PUBKEY);

	case DELETE_Must_Delete_Secret_Key:
	  return gpg_error (GPG_ERR_CONFLICT);

	case DELETE_Ambiguous_Specification:
	  return gpg_error (GPG_ERR_AMBIGUOUS_NAME);

	}

      return gpg_error (GPG_ERR_GENERAL);
    }
  else if (code == GPGME_STATUS_ERROR)
    {
      /* Some error stati are informational, so we don't return an
         error code if we are not ready to process this status.  */
      gpgme_error_t err;
      char *where = strchr (args, ' ');
      char *which;

      if (where)
	{
	  *where = '\0';
	  which = where + 1;

	  where = strchr (which, ' ');
	  if (where)
	    *where = '\0';

	  where = args;
	}
      else
	return trace_gpg_error (GPG_ERR_INV_ENGINE);

      err = atoi (which);

      if (!strcmp (where, "delete_key.secret")
	  && (gpg_err_code (err) == GPG_ERR_CANCELED
	      || gpg_err_code (err) == GPG_ERR_FULLY_CANCELED))
	{
	  /* This indicates a user cancellation on the confirmation dialog.  */
	  return gpg_error (gpg_err_code (err));
	}
    }
  return 0;
}


static gpgme_error_t
delete_start (gpgme_ctx_t ctx, int synchronous, const gpgme_key_t key,
	      int allow_secret)
{
  gpgme_error_t err;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  _gpgme_engine_set_status_handler (ctx->engine, delete_status_handler, ctx);

  return _gpgme_engine_op_delete (ctx->engine, key, allow_secret);
}


/* Delete KEY from the keyring.  If ALLOW_SECRET is non-zero, secret
   keys are also deleted.  */
gpgme_error_t
gpgme_op_delete_start (gpgme_ctx_t ctx, const gpgme_key_t key,
		       int allow_secret)
{
  gpgme_error_t err;

  TRACE_BEG3 (DEBUG_CTX, "gpgme_op_delete", ctx,
	      "key=%p (%s), allow_secret=%i", key,
	      (key->subkeys && key->subkeys->fpr) ?
	      key->subkeys->fpr : "invalid", allow_secret);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = delete_start (ctx, 0, key, allow_secret);
  return TRACE_ERR (err);
}


/* Delete KEY from the keyring.  If ALLOW_SECRET is non-zero, secret
   keys are also deleted.  */
gpgme_error_t
gpgme_op_delete (gpgme_ctx_t ctx, const gpgme_key_t key, int allow_secret)
{
  gpgme_error_t err;

  TRACE_BEG3 (DEBUG_CTX, "gpgme_op_delete", ctx,
	      "key=%p (%s), allow_secret=%i", key,
	      (key->subkeys && key->subkeys->fpr) ?
	      key->subkeys->fpr : "invalid", allow_secret);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = delete_start (ctx, 1, key, allow_secret);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return err;
}
