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
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "gpgme.h"
#include "context.h"
#include "ops.h"


gpgme_error_t
_gpgme_op_data_lookup (gpgme_ctx_t ctx, ctx_op_data_id_t type, void **hook,
		       int size, void (*cleanup) (void *))
{
  struct ctx_op_data *data = ctx->op_data;
  while (data && data->type != type)
    data = data->next;
  if (!data)
    {
      if (size < 0)
	{
	  *hook = NULL;
	  return 0;
	}

      data = calloc (1, sizeof (struct ctx_op_data) + size);
      if (!data)
	return gpg_error_from_errno (errno);
      data->next = ctx->op_data;
      data->type = type;
      data->cleanup = cleanup;
      data->hook = ((void *) data) + sizeof (struct ctx_op_data);
      ctx->op_data = data;
    }
  *hook = data->hook;
  return 0;
}


/* type is: 0: asynchronous operation (use global or user event loop).
            1: synchronous operation (always use private event loop).
            2: asynchronous private operation (use private or user
            event loop).  */
gpgme_error_t
_gpgme_op_reset (gpgme_ctx_t ctx, int type)
{
  gpgme_error_t err = 0;
  struct gpgme_io_cbs io_cbs;

  _gpgme_release_result (ctx);

  /* Create an engine object.  */
  if  (ctx->engine)
    {
      _gpgme_engine_release (ctx->engine);
      ctx->engine = NULL;
    }
  err = _gpgme_engine_new (ctx->protocol, &ctx->engine,
			   ctx->lc_ctype, ctx->lc_messages);
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


gpgme_error_t
_gpgme_parse_inv_recp (char *args, gpgme_invalid_key_t *key)
{
  gpgme_invalid_key_t inv_key;
  char *tail;
  long int reason;

  inv_key = malloc (sizeof (*inv_key));
  if (!inv_key)
    return gpg_error_from_errno (errno);
  inv_key->next = NULL;
  errno = 0;
  reason = strtol (args, &tail, 0);
  if (errno || args == tail || *tail != ' ')
    {
      /* The crypto backend does not behave.  */
      free (inv_key);
      return gpg_error (GPG_ERR_INV_ENGINE);
    }

  switch (reason)
    {
    default:
    case 0:
      inv_key->reason = gpg_error (GPG_ERR_GENERAL);
      break;

    case 1:
      inv_key->reason = gpg_error (GPG_ERR_NO_PUBKEY);
      break;

    case 2:
      inv_key->reason = gpg_error (GPG_ERR_AMBIGUOUS_NAME);
      break;

    case 3:
      inv_key->reason = gpg_error (GPG_ERR_WRONG_KEY_USAGE);
      break;

    case 4:
      inv_key->reason = gpg_error (GPG_ERR_CERT_REVOKED);
      break;

    case 5:
      inv_key->reason = gpg_error (GPG_ERR_CERT_EXPIRED);
      break;

    case 6:
      inv_key->reason = gpg_error (GPG_ERR_NO_CRL_KNOWN);
      break;

    case 7:
      inv_key->reason = gpg_error (GPG_ERR_CRL_TOO_OLD);
      break;

    case 8:
      inv_key->reason = gpg_error (GPG_ERR_NO_POLICY_MATCH);
      break;

    case 9:
      inv_key->reason = gpg_error (GPG_ERR_NO_SECKEY);
      break;

    case 10:
      inv_key->reason = gpg_error (GPG_ERR_PUBKEY_NOT_TRUSTED);
      break;
    }

  while (*tail == ' ')
    tail++;
  if (*tail)
    {
      inv_key->fpr = strdup (tail);
      if (!inv_key->fpr)
	{
	  int saved_errno = errno;
	  free (inv_key);
	  return gpg_error_from_errno (saved_errno);
	}
    }
  else
    inv_key->fpr = NULL;

  *key = inv_key;
  return 0;
}
