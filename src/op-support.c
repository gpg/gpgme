/* op-support.c - Supporting functions.
   Copyright (C) 2002, 2003, 2004, 2007 g10 Code GmbH

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
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include "gpgme.h"
#include "context.h"
#include "ops.h"
#include "util.h"


gpgme_error_t
_gpgme_op_data_lookup (gpgme_ctx_t ctx, ctx_op_data_id_t type, void **hook,
		       int size, void (*cleanup) (void *))
{
  struct ctx_op_data *data;

  if (!ctx)
    return gpg_error (GPG_ERR_INV_VALUE);

  data = ctx->op_data;
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
      data->magic = CTX_OP_DATA_MAGIC;
      data->next = ctx->op_data;
      data->type = type;
      data->cleanup = cleanup;
      data->hook = (void *) (((char *) data) + sizeof (struct ctx_op_data));
      data->references = 1;
      ctx->op_data = data;
    }
  *hook = data->hook;
  return 0;
}


/* type is: 0: asynchronous operation (use global or user event loop).
            1: synchronous operation (always use private event loop).
            2: asynchronous private operation (use private or user
            event loop).  
            256: Modification flag to suppress the engine reset.
*/
gpgme_error_t
_gpgme_op_reset (gpgme_ctx_t ctx, int type)
{
  gpgme_error_t err = 0;
  struct gpgme_io_cbs io_cbs;
  int no_reset = (type & 256);
  int reuse_engine = 0;

  type &= 255;

  _gpgme_release_result (ctx);
  LOCK (ctx->lock);
  ctx->canceled = 0;
  UNLOCK (ctx->lock);

  if (ctx->engine && no_reset)
    reuse_engine = 1;
  else if (ctx->engine)
    {
      /* Attempt to reset an existing engine.  */

      err = _gpgme_engine_reset (ctx->engine);
      if (gpg_err_code (err) == GPG_ERR_NOT_IMPLEMENTED)
	{
	  _gpgme_engine_release (ctx->engine);
	  ctx->engine = NULL;
	}
    }

  if (!ctx->engine)
    {
      gpgme_engine_info_t info;
      info = ctx->engine_info;
      while (info && info->protocol != ctx->protocol)
	info = info->next;

      if (!info)
	return gpg_error (GPG_ERR_UNSUPPORTED_PROTOCOL);

      /* Create an engine object.  */
      err = _gpgme_engine_new (info, &ctx->engine);
      if (err)
	return err;
    }

  if (!reuse_engine)
    {
      err = 0;
#ifdef LC_CTYPE
      err = _gpgme_engine_set_locale (ctx->engine, LC_CTYPE, ctx->lc_ctype);
#endif
#ifdef LC_MESSAGES
      if (!err)
        err = _gpgme_engine_set_locale (ctx->engine,
                                        LC_MESSAGES, ctx->lc_messages);
#endif
      if (gpg_err_code (err) == GPG_ERR_NOT_IMPLEMENTED)
	err = 0;
      if (err)
        {
          _gpgme_engine_release (ctx->engine);
          ctx->engine = NULL;
          return err;
        }
    }

  if (ctx->sub_protocol != GPGME_PROTOCOL_DEFAULT)
    {
      err = _gpgme_engine_set_protocol (ctx->engine, ctx->sub_protocol);
      if (err)
	return err;
    }

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


/* Parse the INV_RECP or INV-SNDR status line in ARGS and return the
   result in KEY.  */
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
  gpg_err_set_errno (0);
  reason = strtol (args, &tail, 0);
  if (errno || args == tail || (*tail && *tail != ' '))
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

    case 11:
      inv_key->reason = gpg_error (GPG_ERR_MISSING_CERT);
      break;

    case 12:
      inv_key->reason = gpg_error (GPG_ERR_MISSING_ISSUER_CERT);
      break;
    }

  while (*tail && *tail == ' ')
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


/* Parse the PLAINTEXT status line in ARGS and return the result in
   FILENAMEP.  */
gpgme_error_t
_gpgme_parse_plaintext (char *args, char **filenamep)
{
  char *tail;

  while (*args == ' ')
    args++;
  if (*args == '\0')
    return 0;

  /* First argument is file type.  */
  while (*args != ' ' && *args != '\0')
    args++;
  while (*args == ' ')
    args++;
  if (*args == '\0')
    return 0;

  /* Second argument is the timestamp.  */
  while (*args != ' ' && *args != '\0')
    args++;
  while (*args == ' ')
    args++;
  if (*args == '\0')
    return 0;

  tail = args;
  while (*tail != ' ' && *tail != '\0')
    tail++;
  *tail = '\0';
  if (filenamep && *args != '\0')
    {
      char *filename = strdup (args);
      if (!filename)
	return gpg_error_from_syserror ();

      *filenamep = filename;
    }
  return 0;
}
