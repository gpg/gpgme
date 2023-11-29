/* op-support.c - Supporting functions.
 * Copyright (C) 2002, 2003, 2004, 2007 g10 Code GmbH
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
#include "debug.h"



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
	return gpg_error_from_syserror ();
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
  ctx->redraw_suggested = 0;
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

      _gpgme_engine_set_engine_flags (ctx->engine, ctx);

      if (!err)
        {
          err = _gpgme_engine_set_pinentry_mode (ctx->engine,
                                                 ctx->pinentry_mode);
          if (gpg_err_code (err) == GPG_ERR_NOT_IMPLEMENTED)
            err = 0;
        }

      if (!err && ctx->status_cb && ctx->full_status)
        {
          _gpgme_engine_set_status_cb (ctx->engine,
                                       ctx->status_cb, ctx->status_cb_value);
        }

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


/* Parse the INV_RECP or INV_SNDR status line in ARGS and return the
   result in KEY.  If KC_FPR (from the KEY_CONSIDERED status line) is
   not NULL take the KC_FLAGS in account. */
gpgme_error_t
_gpgme_parse_inv_recp (char *args, int for_signing,
                       const char *kc_fpr, unsigned int kc_flags,
                       gpgme_invalid_key_t *key)
{
  gpgme_invalid_key_t inv_key;
  char *tail;
  long int reason;

  (void)for_signing;

  inv_key = calloc (1, sizeof (*inv_key));
  if (!inv_key)
    return gpg_error_from_syserror ();
  inv_key->next = NULL;
  gpg_err_set_errno (0);
  reason = strtol (args, &tail, 0);
  if (errno || args == tail || (*tail && *tail != ' '))
    {
      /* The crypto backend does not behave.  */
      free (inv_key);
      return trace_gpg_error (GPG_ERR_INV_ENGINE);
    }

  switch (reason)
    {
    case 0:
      if (kc_fpr && (kc_flags & 2))
        inv_key->reason = gpg_error (GPG_ERR_SUBKEYS_EXP_OR_REV);
      else
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

    case 13:
      inv_key->reason = gpg_error (252); /*GPG_ERR_KEY_DISABLED*/
      break;

    case 14:
      inv_key->reason = gpg_error (GPG_ERR_INV_USER_ID);
      break;

    default:
      inv_key->reason = gpg_error (GPG_ERR_GENERAL);
      break;
    }

  while (*tail && *tail == ' ')
    tail++;
  if (*tail)
    {
      inv_key->fpr = strdup (tail);
      if (!inv_key->fpr)
	{
	  free (inv_key);
	  return gpg_error_from_syserror ();
	}
    }

  *key = inv_key;
  return 0;
}



/* Parse a KEY_CONSIDERED status line in ARGS and store the
 * fingerprint and the flags at R_FPR and R_FLAGS.  The caller must
 * free the value at R_FPR on success.  */
gpgme_error_t
_gpgme_parse_key_considered (const char *args,
                             char **r_fpr, unsigned int *r_flags)
{
  char *pend;
  size_t n;

  *r_fpr = NULL;

  pend = strchr (args, ' ');
  if (!pend || pend == args)
    return trace_gpg_error (GPG_ERR_INV_ENGINE);  /* Bogus status line.  */
  n = pend - args;
  *r_fpr = malloc (n + 1);
  if (!*r_fpr)
    return gpg_error_from_syserror ();
  memcpy (*r_fpr, args, n);
  (*r_fpr)[n] = 0;
  args = pend + 1;

  gpg_err_set_errno (0);
  *r_flags = strtoul (args, &pend, 0);
  if (errno || args == pend || (*pend && *pend != ' '))
    {
      free (*r_fpr);
      *r_fpr = NULL;
      return trace_gpg_error (GPG_ERR_INV_ENGINE);
    }

  return 0;
}


/* Parse the PLAINTEXT status line in ARGS and return the result in
   FILENAMEP.  */
gpgme_error_t
_gpgme_parse_plaintext (char *args, char **filenamep, int *r_mime)
{
  char *tail;

  while (*args == ' ')
    args++;
  if (*args == '\0')
    return 0;

  /* First argument is file type (a one byte uppercase hex value).  */
  if (args[0] == '6' && args[1] == 'D')
    *r_mime = 1;
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
      gpgme_error_t err = 0;
      char *filename = NULL;

      err = _gpgme_decode_percent_string (args, &filename, 0, 0);
      if (err)
        return err;

      *filenamep = filename;
    }
  return 0;
}


/* Parse a FAILURE status line and return the error code.  ARGS is
 * modified to contain the location part.  Note that for now we ignore
 * failure codes with a location of gpg-exit; they are too trouble
 * some.  Instead we should eventually record that error in the
 * context and provide a function to return a fuller error
 * description; this could then also show the location of the error
 * (e.g. "option- parser") to make it easier for the user to detect
 * the actual error. */
gpgme_error_t
_gpgme_parse_failure (char *args)
{
  char *where, *which;

  if (!strncmp (args, "gpg-exit", 8))
    return 0;

  where = strchr (args, ' ');
  if (!where)
    return trace_gpg_error (GPG_ERR_INV_ENGINE);

  *where = '\0';
  which = where + 1;

  where = strchr (which, ' ');
  if (where)
    *where = '\0';

  return atoi (which);
}
