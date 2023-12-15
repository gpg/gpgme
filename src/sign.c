/* sign.c - Signing function.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004, 2007 g10 Code GmbH
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

/* Suppress warning for accessing deprecated member "class".  */
#define _GPGME_IN_GPGME 1
#include "gpgme.h"
#include "context.h"
#include "ops.h"
#include "util.h"
#include "debug.h"


typedef struct
{
  struct _gpgme_op_sign_result result;

  /* The error code from a FAILURE status line or 0.  */
  gpg_error_t failure_code;

  /* The fingerprint from the last KEY_CONSIDERED status line.  */
  char *kc_fpr;

  /* The flags from the last KEY_CONSIDERED status line.  */
  unsigned int kc_flags;

  /* A pointer to the next pointer of the last invalid signer in
     the list.  This makes appending new invalid signers painless
     while preserving the order.  */
  gpgme_invalid_key_t *last_signer_p;

  /* Likewise for signature information.  */
  gpgme_new_signature_t *last_sig_p;

  /* Flags used while processing the status lines.  */
  unsigned int ignore_inv_recp:1;
  unsigned int inv_sgnr_seen:1;
  unsigned int sig_created_seen:1;
} *op_data_t;


static void
release_signatures (gpgme_new_signature_t sig)
{
  while (sig)
    {
      gpgme_new_signature_t next = sig->next;
      free (sig->fpr);
      free (sig);
      sig = next;
    }
}


static void
release_op_data (void *hook)
{
  op_data_t opd = (op_data_t) hook;
  gpgme_invalid_key_t invalid_signer = opd->result.invalid_signers;

  while (invalid_signer)
    {
      gpgme_invalid_key_t next = invalid_signer->next;
      if (invalid_signer->fpr)
	free (invalid_signer->fpr);
      free (invalid_signer);
      invalid_signer = next;
    }

  release_signatures (opd->result.signatures);
  free (opd->kc_fpr);
}


gpgme_sign_result_t
gpgme_op_sign_result (gpgme_ctx_t ctx)
{
  void *hook;
  op_data_t opd;
  gpgme_error_t err;
  gpgme_invalid_key_t inv_key, key;
  gpgme_new_signature_t sig;
  unsigned int inv_signers = 0;
  unsigned int signatures = 0;

  TRACE_BEG (DEBUG_CTX, "gpgme_op_sign_result", ctx, "");

  err = _gpgme_op_data_lookup (ctx, OPDATA_SIGN, &hook, -1, NULL);
  opd = hook;
  if (err || !opd)
    {
      TRACE_SUC ("result=(null)");
      return NULL;
    }

  for (inv_key = opd->result.invalid_signers; inv_key; inv_key = inv_key->next)
    inv_signers++;
  for (sig = opd->result.signatures; sig; sig = sig->next)
    signatures++;

  if (gpgme_signers_count (ctx)
      && signatures + inv_signers != gpgme_signers_count (ctx))
    {
      /* In this case at least one signature was not created perhaps
         due to a bad passphrase etc.  Thus the entire message is
         broken and should not be used.  We add the already created
         signatures to the invalid signers list and thus this case can
         be detected.  */
      TRACE_LOG  ("result: invalid signers: %u, signatures: %u, count: %u",
                  inv_signers, signatures, gpgme_signers_count (ctx));

      for (sig = opd->result.signatures; sig; sig = sig->next)
        {
          key = calloc (1, sizeof *key);
          if (!key)
            {
              TRACE_SUC ("out of core; result=(null)");
              return NULL;
            }
          if (sig->fpr)
            {
              key->fpr = strdup (sig->fpr);
              if (!key->fpr)
                {
                  free (key);
                  TRACE_SUC ("out of core; result=(null)");
                  return NULL;
                }
            }
          key->reason = GPG_ERR_GENERAL;

          inv_key = opd->result.invalid_signers;
          if (inv_key)
            {
              for (; inv_key->next; inv_key = inv_key->next)
                ;
              inv_key->next = key;
            }
          else
            opd->result.invalid_signers = key;
        }

      release_signatures (opd->result.signatures);
      opd->result.signatures = NULL;
    }

  if (_gpgme_debug_trace())
    {
      TRACE_LOG  ("result: invalid signers: %i, signatures: %i",
		  inv_signers, signatures);
      for (inv_key=opd->result.invalid_signers; inv_key; inv_key=inv_key->next)
	{
	  TRACE_LOG  ("result: invalid signer: fpr=%s, reason=%s <%s>",
		      inv_key->fpr, gpgme_strerror (inv_key->reason),
		      gpgme_strsource (inv_key->reason));
	}
      for (sig = opd->result.signatures; sig; sig = sig->next)
	{
	  TRACE_LOG  ("result: signature: type=%i, pubkey_algo=%i, "
		      "hash_algo=%i, timestamp=%li, fpr=%s, sig_class=%i",
		      sig->type, sig->pubkey_algo, sig->hash_algo,
		      sig->timestamp, sig->fpr, sig->sig_class);
	}
   }

  TRACE_SUC ("result=%p", &opd->result);
  return &opd->result;
}



static gpgme_error_t
parse_sig_created (char *args, gpgme_new_signature_t *sigp,
                   gpgme_protocol_t protocol)
{
  gpgme_new_signature_t sig;
  char *tail;

  sig = malloc (sizeof (*sig));
  if (!sig)
    return gpg_error_from_syserror ();

  sig->next = NULL;
  switch (*args)
    {
    case 'S':
      sig->type = GPGME_SIG_MODE_NORMAL;
      break;

    case 'D':
      sig->type = GPGME_SIG_MODE_DETACH;
      break;

    case 'C':
      sig->type = GPGME_SIG_MODE_CLEAR;
      break;

    default:
      /* The backend engine is not behaving.  */
      free (sig);
      return trace_gpg_error (GPG_ERR_INV_ENGINE);
    }

  args++;
  if (*args != ' ')
    {
      free (sig);
      return trace_gpg_error (GPG_ERR_INV_ENGINE);
    }

  gpg_err_set_errno (0);
  sig->pubkey_algo = _gpgme_map_pk_algo (strtol (args, &tail, 0), protocol);
  if (errno || args == tail || *tail != ' ')
    {
      /* The crypto backend does not behave.  */
      free (sig);
      return trace_gpg_error (GPG_ERR_INV_ENGINE);
    }
  args = tail;

  sig->hash_algo = strtol (args, &tail, 0);
  if (errno || args == tail || *tail != ' ')
    {
      /* The crypto backend does not behave.  */
      free (sig);
      return trace_gpg_error (GPG_ERR_INV_ENGINE);
    }
  args = tail;

  /* strtol has been used wrongly here.  We can't change this anymore
   * but we now take care of the 0x1f class which would otherwise let
   * us run into an error.  */
  sig->sig_class = strtol (args, &tail, 0);
  if (!errno && args != tail && sig->sig_class == 1
      && (*tail == 'F' || *tail == 'f'))
    {
      tail++;
      sig->sig_class = 131; /* Arbitrary unused value in rfc4880. */
    }
  sig->class = sig->sig_class;
  sig->_obsolete_class = sig->sig_class;
  if (errno || args == tail || *tail != ' ')
    {
      /* The crypto backend does not behave.  */
      free (sig);
      return trace_gpg_error (GPG_ERR_INV_ENGINE);
    }
  args = tail;

  sig->timestamp = _gpgme_parse_timestamp (args, &tail);
  if (sig->timestamp == -1 || args == tail || *tail != ' ')
    {
      /* The crypto backend does not behave.  */
      free (sig);
      return trace_gpg_error (GPG_ERR_INV_ENGINE);
    }
  args = tail;
  while (*args == ' ')
    args++;

  if (!*args)
    {
      /* The crypto backend does not behave.  */
      free (sig);
      return trace_gpg_error (GPG_ERR_INV_ENGINE);
    }

  tail = strchr (args, ' ');
  if (tail)
    *tail = '\0';

  sig->fpr = strdup (args);
  if (!sig->fpr)
    {
      free (sig);
      return gpg_error_from_syserror ();
    }
  *sigp = sig;
  return 0;
}


gpgme_error_t
_gpgme_sign_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_passphrase_status_handler (priv, code, args);
  if (err)
    return err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_SIGN, &hook, -1, NULL);
  opd = hook;
  if (err)
    return err;

  switch (code)
    {
    case GPGME_STATUS_SIG_CREATED:
      opd->sig_created_seen = 1;
      err = parse_sig_created (args, opd->last_sig_p, ctx->protocol);
      if (err)
	return err;

      opd->last_sig_p = &(*opd->last_sig_p)->next;
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
      if (opd->inv_sgnr_seen && opd->ignore_inv_recp)
        break;
      /* FALLTHROUGH */
    case GPGME_STATUS_INV_SGNR:
      if (code == GPGME_STATUS_INV_SGNR)
        opd->inv_sgnr_seen = 1;
      free (opd->kc_fpr);
      opd->kc_fpr = NULL;
      err = _gpgme_parse_inv_recp (args, 1, opd->kc_fpr, opd->kc_flags,
                                   opd->last_signer_p);
      if (err)
	return err;

      opd->last_signer_p = &(*opd->last_signer_p)->next;
      free (opd->kc_fpr);
      opd->kc_fpr = NULL;
      break;

    case GPGME_STATUS_FAILURE:
      if (!opd->failure_code
          || gpg_err_code (opd->failure_code) == GPG_ERR_GENERAL)
        opd->failure_code = _gpgme_parse_failure (args);
      break;

    case GPGME_STATUS_EOF:
      /* The UI server does not send information about the created
         signature.  This is irrelevant for this protocol and thus we
         should not check for that.  */
      if (opd->result.invalid_signers)
	err = gpg_error (GPG_ERR_UNUSABLE_SECKEY);
      else if (!opd->sig_created_seen
               && ctx->protocol != GPGME_PROTOCOL_UISERVER)
	err = opd->failure_code? opd->failure_code:gpg_error (GPG_ERR_GENERAL);
      break;

    case GPGME_STATUS_INQUIRE_MAXLEN:
      if (ctx->status_cb && !ctx->full_status)
        err = ctx->status_cb (ctx->status_cb_value, "INQUIRE_MAXLEN", args);
      break;

    default:
      break;
    }
  return err;
}


static gpgme_error_t
sign_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  gpgme_error_t err;

  err = _gpgme_progress_status_handler (priv, code, args);
  if (!err)
    err = _gpgme_sign_status_handler (priv, code, args);
  return err;
}


static gpgme_error_t
sign_init_result (gpgme_ctx_t ctx, int ignore_inv_recp)
{
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_op_data_lookup (ctx, OPDATA_SIGN, &hook,
			       sizeof (*opd), release_op_data);
  opd = hook;
  if (err)
    return err;
  opd->failure_code = 0;
  opd->last_signer_p = &opd->result.invalid_signers;
  opd->last_sig_p = &opd->result.signatures;
  opd->ignore_inv_recp = !!ignore_inv_recp;
  opd->inv_sgnr_seen = 0;
  opd->sig_created_seen = 0;
  return 0;
}

gpgme_error_t
_gpgme_op_sign_init_result (gpgme_ctx_t ctx)
{
  return sign_init_result (ctx, 0);
}


static gpgme_error_t
sign_start (gpgme_ctx_t ctx, int synchronous, gpgme_data_t plain,
	    gpgme_data_t sig, gpgme_sig_mode_t flags)
{
  gpgme_error_t err;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  /* If we are using the CMS protocol, we ignore the INV_RECP status
     code if a newer GPGSM is in use.  GPGMS does not support combined
     sign+encrypt and thus this can't harm.  */
  err = sign_init_result (ctx, (ctx->protocol == GPGME_PROTOCOL_CMS));
  if (err)
    return err;

  if (flags & ~(GPGME_SIG_MODE_DETACH
                |GPGME_SIG_MODE_CLEAR
                |GPGME_SIG_MODE_ARCHIVE
                |GPGME_SIG_MODE_FILE))
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!plain)
    return gpg_error (GPG_ERR_NO_DATA);
  if (!sig)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (ctx->passphrase_cb)
    {
      err = _gpgme_engine_set_command_handler
	(ctx->engine, _gpgme_passphrase_command_handler, ctx);
      if (err)
	return err;
    }

  _gpgme_engine_set_status_handler (ctx->engine, sign_status_handler,
				    ctx);

  return _gpgme_engine_op_sign (ctx->engine, plain, sig, flags, ctx->use_armor,
				ctx->use_textmode, ctx->include_certs,
				ctx /* FIXME */);
}


/* Sign the plaintext PLAIN and store the signature in SIG.  */
gpgme_error_t
gpgme_op_sign_start (gpgme_ctx_t ctx, gpgme_data_t plain, gpgme_data_t sig,
		     gpgme_sig_mode_t flags)
{
  gpg_error_t err;
  TRACE_BEG  (DEBUG_CTX, "gpgme_op_sign_start", ctx,
	      "plain=%p, sig=%p, flags=%i", plain, sig, flags);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = sign_start (ctx, 0, plain, sig, flags);
  return TRACE_ERR (err);
}


/* Sign the plaintext PLAIN and store the signature in SIG.  */
gpgme_error_t
gpgme_op_sign (gpgme_ctx_t ctx, gpgme_data_t plain, gpgme_data_t sig,
	       gpgme_sig_mode_t flags)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_sign", ctx,
	      "plain=%p, sig=%p, flags=%i", plain, sig, flags);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = sign_start (ctx, 1, plain, sig, flags);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}
