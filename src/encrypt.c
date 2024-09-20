/* encrypt.c - Encrypt function.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004 g10 Code GmbH
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
#include <string.h>
#include <errno.h>

#include "gpgme.h"
#include "debug.h"
#include "context.h"
#include "ops.h"


typedef struct
{
  struct _gpgme_op_encrypt_result result;

  /* The error code from a FAILURE status line or 0.  */
  gpg_error_t failure_code;

  /* The fingerprint from the last KEY_CONSIDERED status line.  */
  char *kc_fpr;

  /* The flags from the last KEY_CONSIDERED status line.  */
  unsigned int kc_flags;

  /* A pointer to the next pointer of the last invalid recipient in
     the list.  This makes appending new invalid recipients painless
     while preserving the order.  */
  gpgme_invalid_key_t *lastp;

  /* Whether a SUCCESS status was seen.  Emitted by gpgtar.  */
  unsigned int success_seen:1;
} *op_data_t;


static void
release_op_data (void *hook)
{
  op_data_t opd = (op_data_t) hook;
  gpgme_invalid_key_t invalid_recipient = opd->result.invalid_recipients;

  while (invalid_recipient)
    {
      gpgme_invalid_key_t next = invalid_recipient->next;
      if (invalid_recipient->fpr)
	free (invalid_recipient->fpr);
      free (invalid_recipient);
      invalid_recipient = next;
    }

  free (opd->kc_fpr);
}


gpgme_encrypt_result_t
gpgme_op_encrypt_result (gpgme_ctx_t ctx)
{
  void *hook;
  op_data_t opd;
  gpgme_error_t err;

  TRACE_BEG (DEBUG_CTX, "gpgme_op_encrypt_result", ctx, "");

  err = _gpgme_op_data_lookup (ctx, OPDATA_ENCRYPT, &hook, -1, NULL);
  opd = hook;

  if (err || !opd)
    {
      TRACE_SUC ("result=(null)");
      return NULL;
    }

  if (_gpgme_debug_trace ())
    {
      gpgme_invalid_key_t invkeys = opd->result.invalid_recipients;
      int i = 0;

      while (invkeys)
	{
	  TRACE_LOG  ("invalid_recipients[%i] = %s (%s)",
		      i, invkeys->fpr ? invkeys->fpr : "(null)",
		      gpg_strerror (invkeys->reason));
	  invkeys = invkeys->next;
	  i++;
	}
    }

  TRACE_SUC ("result=%p", &opd->result);
  return &opd->result;
}


gpgme_error_t
_gpgme_encrypt_status_handler (void *priv, gpgme_status_code_t code,
			       char *args)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_op_data_lookup (ctx, OPDATA_ENCRYPT, &hook, -1, NULL);
  opd = hook;
  if (err)
    return err;

  switch (code)
    {
    case GPGME_STATUS_FAILURE:
      if (!opd->failure_code
          || gpg_err_code (opd->failure_code) == GPG_ERR_GENERAL)
        opd->failure_code = _gpgme_parse_failure (args);
      break;

    case GPGME_STATUS_EOF:
      if (opd->result.invalid_recipients)
	return gpg_error (GPG_ERR_UNUSABLE_PUBKEY);
      if (opd->failure_code)
        return opd->failure_code;
      if (!opd->success_seen)
        return gpg_error (GPG_ERR_EOF);
      break;

    case GPGME_STATUS_KEY_CONSIDERED:
      /* This is emitted during gpg's key lookup to give information
       * about the lookup results.  We store the last one so it can be
       * used in connection with INV_RECP.  */
      free (opd->kc_fpr);
      opd->kc_fpr = NULL;
      err = _gpgme_parse_key_considered (args, &opd->kc_fpr, &opd->kc_flags);
      if (err)
        return err;
      break;

    case GPGME_STATUS_INV_RECP:
      err = _gpgme_parse_inv_recp (args, 0, opd->kc_fpr, opd->kc_flags,
                                   opd->lastp);
      if (err)
        return err;

      opd->lastp = &(*opd->lastp)->next;
      free (opd->kc_fpr);
      opd->kc_fpr = NULL;
      break;

    case GPGME_STATUS_NO_RECP:
      /* Should not happen, because we require at least one recipient.  */
      return gpg_error (GPG_ERR_GENERAL);

    case GPGME_STATUS_SUCCESS:
      opd->success_seen = 1;
      break;

    default:
      break;
    }
  return 0;
}


static gpgme_error_t
encrypt_sym_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  gpgme_error_t err;

  err = _gpgme_progress_status_handler (priv, code, args);
  if (!err)
    err = _gpgme_passphrase_status_handler (priv, code, args);
  if (!err)
    err = _gpgme_encrypt_status_handler (priv, code, args);
  return err;
}


static gpgme_error_t
encrypt_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  gpgme_error_t err;

  err = _gpgme_progress_status_handler (priv, code, args);
  if (!err)
    err = _gpgme_encrypt_status_handler (priv, code, args);

  return err;
}


gpgme_error_t
_gpgme_op_encrypt_init_result (gpgme_ctx_t ctx, int success_required)
{
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_op_data_lookup (ctx, OPDATA_ENCRYPT, &hook, sizeof (*opd),
			       release_op_data);
  opd = hook;
  if (err)
    return err;

  opd->lastp = &opd->result.invalid_recipients;
  opd->success_seen = !success_required;
  return 0;
}


static gpgme_error_t
encrypt_start (gpgme_ctx_t ctx, int synchronous, gpgme_key_t recp[],
               const char *recpstring,
	       gpgme_encrypt_flags_t flags,
	       gpgme_data_t plain, gpgme_data_t cipher)
{
  gpgme_error_t err;
  int symmetric = 0;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  err = _gpgme_op_encrypt_init_result (ctx, flags & GPGME_ENCRYPT_ARCHIVE);
  if (err)
    return err;

  symmetric = (!recp && !recpstring) || (flags & GPGME_ENCRYPT_SYMMETRIC);

  if (!plain)
    return gpg_error (GPG_ERR_NO_DATA);
  if (!cipher)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (recp && !*recp)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (symmetric && ctx->passphrase_cb)
    {
      /* Symmetric encryption requires a passphrase.  */
      err = _gpgme_engine_set_command_handler
	(ctx->engine, _gpgme_passphrase_command_handler, ctx);
      if (err)
	return err;
    }

  _gpgme_engine_set_status_handler (ctx->engine,
				    symmetric
				    ? encrypt_sym_status_handler
				    : encrypt_status_handler,
				    ctx);

  return _gpgme_engine_op_encrypt (ctx->engine, recp, recpstring,
                                   flags, plain, cipher, ctx->use_armor);
}


/* Old version of gpgme_op_encrypt_ext without RECPSTRING.  */
gpgme_error_t
gpgme_op_encrypt (gpgme_ctx_t ctx, gpgme_key_t recp[],
		  gpgme_encrypt_flags_t flags,
		  gpgme_data_t plain, gpgme_data_t cipher)
{
  return gpgme_op_encrypt_ext (ctx, recp, NULL, flags, plain, cipher);
}


/* Old version of gpgme_op_encrypt_ext_start without RECPSTRING.  */
gpgme_error_t
gpgme_op_encrypt_start (gpgme_ctx_t ctx, gpgme_key_t recp[],
			gpgme_encrypt_flags_t flags,
			gpgme_data_t plain, gpgme_data_t cipher)
{
  return gpgme_op_encrypt_ext_start (ctx, recp, NULL, flags, plain, cipher);
}


/* Encrypt plaintext PLAIN within CTX for the recipients RECP and
 * store the resulting ciphertext in CIPHER.  RECPSTRING can be used
 * instead of the RECP array to directly specify recipients as LF
 * delimited strings; these may be any kind of recipient specification
 * patterns as supported by the backend.  */
gpgme_error_t
gpgme_op_encrypt_ext (gpgme_ctx_t ctx, gpgme_key_t recp[],
                      const char *recpstring,
                      gpgme_encrypt_flags_t flags,
                      gpgme_data_t plain, gpgme_data_t cipher)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_encrypt", ctx,
	      "flags=0x%x, plain=%p, cipher=%p", flags, plain, cipher);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (_gpgme_debug_trace () && (recp || recpstring))
    {
      if (recp)
        {
          int i = 0;

          while (recp[i])
            {
              TRACE_LOG  ("recipient[%i] = %p (%s)", i, recp[i],
		      (recp[i]->subkeys && recp[i]->subkeys->fpr) ?
                          recp[i]->subkeys->fpr : "invalid");
              i++;
            }
        }
      else
        {
          TRACE_LOG  ("recipients = '%s'", recpstring);
        }
    }

  err = encrypt_start (ctx, 1, recp, recpstring, flags, plain, cipher);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}


gpgme_error_t
gpgme_op_encrypt_ext_start (gpgme_ctx_t ctx, gpgme_key_t recp[],
                            const char *recpstring,
                            gpgme_encrypt_flags_t flags,
                            gpgme_data_t plain, gpgme_data_t cipher)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_encrypt_start", ctx,
	      "flags=0x%x, plain=%p, cipher=%p", flags, plain, cipher);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (_gpgme_debug_trace () && (recp || recpstring))
    {
      if (recp)
        {
          int i = 0;

          while (recp[i])
            {
              TRACE_LOG  ("recipient[%i] = %p (%s)", i, recp[i],
                          (recp[i]->subkeys && recp[i]->subkeys->fpr) ?
                          recp[i]->subkeys->fpr : "invalid");
              i++;
            }
        }
      else
        {
          TRACE_LOG  ("recipients = '%s'", recpstring);
        }
    }

  err = encrypt_start (ctx, 0, recp, recpstring, flags, plain, cipher);
  return TRACE_ERR (err);
}
